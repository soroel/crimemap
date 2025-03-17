from flask import Flask, jsonify, render_template, request
import dbconfig
import json
import pandas as pd
import os
from flask_cors import CORS

# Use appropriate database helper
if dbconfig.test:
    from mockdbhelper import MockDBHelper as DBHelper
else:
    from dbhelper import DBHelper

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})  # Restrict CORS
DB = DBHelper()

# Categories of crimes
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

# Load dataset
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
data_file_path = os.path.join(BASE_DIR, "hello_ds", "crimedata-clean.csv")

try:
    data = pd.read_csv(data_file_path)
    data["Counties"] = data["Counties"].str.strip().str.lower()  # Normalize case
    data.dropna(subset=["Counties"], inplace=True)
    print("✅ Data loaded successfully.")
except Exception as e:
    print(f"❌ Error loading data: {e}")
    data = pd.DataFrame()


@app.route("/")
def home():
    crimes = DB.get_all_crimes()
    return render_template(
        "home.html", crimes=json.dumps(crimes), categories=categories
    )


@app.route("/api/filter-crimes", methods=["POST"])
def filter_crimes():
    request_data = request.json
    county = request_data.get("county", "").strip().lower()

    if not county:
        return jsonify({"error": "Missing 'county' parameter"}), 400

    filtered_data = data[data["Counties"] == county]

    if filtered_data.empty:
        return jsonify({"error": f"No data found for county '{county}'"}), 404

    try:
        chart_data = filtered_data.drop(
            columns=["Counties", "Total", "COUNTIES VS CATEGORY"], errors="ignore"
        ).sum()

        labels, values = chart_data.index.tolist(), chart_data.values.tolist()

        return jsonify(labels=labels, values=values)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/heatmap-data")
def get_heatmap_data():
    return jsonify(
        [
            {"latitude": -1.286389, "longitude": 36.817223, "intensity": 5},  # Nairobi
            {"latitude": -0.425, "longitude": 36.9476, "intensity": 3},  # Nakuru
            {"latitude": -4.0435, "longitude": 39.6682, "intensity": 2},  # Mombasa
            {"latitude": -0.1022, "longitude": 34.7617, "intensity": 4},  # Kisumu
            {"latitude": 0.5167, "longitude": 35.2833, "intensity": 1},  # Eldoret
        ]
    )


@app.route("/api/submitcrime", methods=["POST"])
def submitcrime():
    try:
        # Check content type
        if request.content_type == "application/json":
            data = request.json  # Expecting JSON
        else:
            data = request.form  # Expecting form-data

        category = data.get("category")
        date = data.get("date")
        latitude = data.get("latitude")
        longitude = data.get("longitude")
        description = data.get("description")

        if not (category and date and latitude and longitude):
            return jsonify({"error": "Missing required fields"}), 400

        latitude = float(latitude)
        longitude = float(longitude)

        DB.add_crime(category, date, latitude, longitude, description)
        return jsonify({"success": "Crime reported successfully"}), 200

    except ValueError:
        return jsonify({"error": "Invalid latitude or longitude"}), 400
    except Exception as e:
        print(f"Error in submitcrime: {e}")
        return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(port=5000, debug=True)
