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
        self.users = {
            "admin": {
                "id": 1,
                "username": "admin",
                "password": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY.5AQGHXqOUiSm",  # "admin123"
                "role": "admin"
            },
            "user": {
                "id": 2,
                "username": "user",
                "password": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY.5AQGHXqOUiSm",  # "user123"
                "role": "user"
            }
        }
        self.alerts = []
        self.crime_reports = []
        self.next_user_id = 3
        self.next_alert_id = 1
        self.next_report_id = 1
        
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
        
    def get_reports_by_user(self, username, page=1, per_page=5):
        """Mock implementation of paginated user reports."""
        # Filter reports for the user
        user_reports = [report for report in self.mock_crimes if report.get('username') == username]
        
        # Calculate pagination
        total_reports = len(user_reports)
        total_pages = (total_reports + per_page - 1) // per_page
        
        # Calculate slice indices
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        
        # Get paginated reports
        paginated_reports = user_reports[start_idx:end_idx]
        
        return {
            "reports": paginated_reports,
            "total_pages": total_pages,
            "total_reports": total_reports
        }
        
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
        """Create a new user in the mock database."""
        if username in self.users:
            return False
            
        self.users[username] = {
            "id": self.next_user_id,
            "username": username,
            "password": hashed_password,
            "role": role
        }
        self.next_user_id += 1
        return True
        
    def get_user(self, username):
        """Get user by username."""
        return self.users.get(username)
        
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

    def update_alert(self, alert_id, alert_data):
        # Always return success in mock mode
        return True

    def delete_alert(self, alert_id):
        # Always return success in mock mode
        return True