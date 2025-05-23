class MockDBHelper:
    def __init__(self):
        self.mock_crimes = [{
            'id': 1, 
            'latitude': -1.286389,
            'longitude': 36.817223,
            'date': "2000-01-01",
            'category': "mugging",
            'description': "mock description",
            'username': "testuser",
            'status': "pending"
        }]
        
    def connect(self, database="crimemap"):
        pass

    def get_all_inputs(self):
        return []

    def add_input(self, data):
        pass

    def clear_all(self):
        pass
        
    def add_crime(self, category, date, latitude, longitude, description, username="Anonymous"):
        new_id = len(self.mock_crimes) + 1
        self.mock_crimes.append({
            'id': new_id,
            'category': category,
            'date': date,
            'latitude': latitude,
            'longitude': longitude,
            'description': description,
            'username': username,
            'status': "pending"
        })
        return True
        
    def get_all_crimes(self):
        return self.mock_crimes
        
    def get_reports_by_user(self, username):
        return [report for report in self.mock_crimes if report.get('username') == username]
        
    def get_report_by_id(self, report_id):
        for report in self.mock_crimes:
            if report.get('id') == report_id:
                return report
        return None
        
    def update_crime(self, report_id, **fields):
        for i, report in enumerate(self.mock_crimes):
            if report.get('id') == report_id:
                for key, value in fields.items():
                    if value is not None:
                        self.mock_crimes[i][key] = value
                return True
        return False
        
    def delete_crime(self, report_id):
        for i, report in enumerate(self.mock_crimes):
            if report.get('id') == report_id:
                self.mock_crimes.pop(i)
                return True
        return False
        
    def get_latest_crimes(self, limit=5):
        return self.mock_crimes[:limit]
        
    def get_alerts_for_user(self, username):
        return []
        
    def create_user(self, username, hashed_password, role="user"):
        return True
        
    def get_user(self, username):
        if username == "admin":
            return {"username": "admin", "password": "$2b$12$q7YRGlZRq2Qxvnr.SqS89O9JrEXKK90Y28b14Pd9fj4L64v.9EyvG", "role": "admin"}
        elif username == "user":
            return {"username": "user", "password": "$2b$12$q7YRGlZRq2Qxvnr.SqS89O9JrEXKK90Y28b14Pd9fj4L64v.9EyvG", "role": "user"}
        return None
        
    def get_all_users(self):
        return [
            {"id": 1, "username": "admin", "role": "admin", "created_at": "2023-01-01 00:00:00"},
            {"id": 2, "username": "user", "role": "user", "created_at": "2023-01-02 00:00:00"}
        ]
        
    def create_alert(self, alert_data):
        return True
        
    def delete_user(self, user_id):
        # Don't allow deleting admin user even in mock mode
        if user_id == 1:  # admin
            return False
        return True
        
    def is_same_user(self, user_id, username):
        if user_id == 1 and username == "admin":
            return True
        if user_id == 2 and username == "user":
            return True
        return False
        
    def update_user(self, user_id, update_data):
        # Don't allow updating admin user's role in mock mode
        if user_id == 1 and update_data.get("role") != "admin":
            return False
        # Simulate success for other cases
        return True
        
    def update_last_login(self, username):
        # Always return success in mock mode
        return True