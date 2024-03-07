from flask import Flask, render_template, request
import dbconfig
import json
if dbconfig.test:
  from mockdbhelper import MockDBHelper as DBHelper
else:
  from dbhelper import DBHelper

app = Flask(__name__)
DB = DBHelper()
categories = ['Homicide', 'Offences against Morality', 
              'Other offences against person', 'Robbery', 'Breaking', 
              'Theft of Stock', 'Stealing', 'Theft by Servant', 
              'Theft of Vehicle and parts', 'Dangerous Drugs', 'Traffic offences', 'Criminal damage', 
              'Economic crimes', 'Corruption', 'Offences Involving police officers', 
              'Offences involving tourists', 'Other penal code offences']
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

@app.route("/analysis")
def analysis():
   return render_template("analysis.html")

@app.route("/submitcrime", methods=['POST'])
def submitcrime():
  category = request.form.get("category")
  date = request.form.get("date")
  latitude = float(request.form.get("latitude"))
  longitude = float(request.form.get("longitude"))
  description = request.form.get("description")
  DB.add_crime(category, date, latitude, longitude, description)
  return home()
if __name__ == '__main__':
    app.run(port=5000, debug=True)

