from flask import Flask, jsonify, render_template, request
import dbconfig
import json
import pandas as pd
import os


if dbconfig.test:
    from mockdbhelper import MockDBHelper as DBHelper
else:
    from dbhelper import DBHelper

app = Flask(__name__)
DB = DBHelper()
categories = [
    "Homicide",
    "Offences against Morality",
    "Other offences against person",
    "Robbery",
    "Breaking",
    "Theft of Stock",
    "Stealing",
    "Theft by Servant",
    "Theft of Vehicle and parts",
    "Dangerous Drugs",
    "Traffic offences",
    "Criminal damage",
    "Economic crimes",
    "Corruption",
    "Offences Involving police officers",
    "Offences involving tourists",
    "Other penal code offences",
]
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
data_file_path = os.path.join(BASE_DIR, "hello_ds", "crimedata-clean.csv")

data = pd.read_csv("hello_ds/crimedata-clean.csv")


@app.route("/")
def home():
    crimes = DB.get_all_crimes()
    crimes = json.dumps(crimes)
    return render_template("home.html", crimes=crimes, categories=categories)


@app.route("/add", methods=["POST"])
def add():
    try:
        data = request.form.get("userinput")
        DB.add_input(data)
    except Exception as e:
        print(e)
    return home()


@app.route("/clear")
def clear():
    try:
        DB.clear_all()
    except Exception as e:
        print(e)
    return home()


@app.route("/crime_map")
def crime_map():
    # Fetch crime data from the database
    crimes = DB.get_all_crimes()
    return render_template("crime-map.html", crimes=crimes)


@app.route("/get-cleaned-data")
def get_cleaned_data():
    # Convert the cleaned data to JSON format
    cleaned_data_json = data.to_dict(orient="records")
    return jsonify(cleaned_data_json)


@app.route("/api/filter-crimes", methods=["POST"])
def filter_crimes():
    county = request.json.get("county")

    print(f"Filtering data for county: {county}")  # Debugging step

    try:
        filtered_data = data[data["Counties"] == county]
        print("Filtered Data:\n", filtered_data)  # Debugging step
    except KeyError as e:
        return jsonify({"error": "Invalid column names for filtering"}), 400

    chart_data = filtered_data.drop(
        columns=["Counties", "Total", "COUNTIES VS CATEGORY"]
    ).sum()

    labels = chart_data.index.tolist()
    values = chart_data.values.tolist()

    print(f"Labels: {labels}")  # Debugging step
    print(f"Values: {values}")  # Debugging step

    return jsonify(labels=labels, values=values)


@app.route("/updates")
def updates():
    return render_template("updates.html")


@app.route("/submitcrime", methods=["POST"])
def submitcrime():
    category = request.form.get("category")
    date = request.form.get("date")
    latitude = float(request.form.get("latitude"))
    longitude = float(request.form.get("longitude"))
    description = request.form.get("description")
    DB.add_crime(category, date, latitude, longitude, description)
    return home()


if __name__ == "__main__":
    app.run(port=5000, debug=True)
