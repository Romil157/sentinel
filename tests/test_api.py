import pytest
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

from app import create_app, db




@pytest.fixture
def client():
    app = create_app('test')
    app.config['TESTING'] = True
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()

def test_health_check(client):
    res = client.get('/api/v1/health/')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'healthy'
    assert 'database' in data

def test_predict_text_endpoint(client):
    payload = {"text": "Urgent! Claim your prize now. Enter your credit card."}
    res = client.post('/api/v1/predict/text', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['input_type'] == 'text'
    assert 'severity_level' in data
    assert 'confidence_score' in data
    assert 'explainability' in data

def test_predict_text_validation(client):
    res = client.post('/api/v1/predict/text', json={})
    assert res.status_code == 400

def test_predict_url_endpoint(client):
    payload = {"url": "http://192.168.0.1/verify-account"}
    res = client.post('/api/v1/predict/url', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['input_type'] == 'url'
    assert data['confidence_score'] > 0.40

def test_predict_batch_endpoint(client):
    payload = {
        "items": [
            "http://paypa1-security.xyz/login",
            "Urgent account suspension notice from bank.",
            "Quarterly developer team sync notes."
        ]
    }
    res = client.post('/api/v1/predict/batch', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['total_processed'] == 3
    assert data['threats_detected'] >= 2
    assert len(data['results']) == 3

def test_feed_endpoint(client):
    res = client.get('/api/v1/feed/')
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert len(data) > 0

def test_history_endpoint(client):
    client.post('/api/v1/predict/text', json={"text": "Hello world test"})
    res = client.get('/api/v1/history/')
    assert res.status_code == 200
    data = res.get_json()
    assert 'items' in data
    assert len(data['items']) > 0

def test_history_export(client):
    # Test JSON export
    res_json = client.get('/api/v1/history/export?format=json')
    assert res_json.status_code == 200
    json_data = res_json.get_json()
    assert 'records' in json_data
    assert 'total_records' in json_data

    # Test CSV export
    res_csv = client.get('/api/v1/history/export?format=csv')
    assert res_csv.status_code == 200
    assert 'text/csv' in res_csv.content_type
    assert b'Severity' in res_csv.data

def test_analytics_endpoints(client):
    res_overview = client.get('/api/v1/analytics/overview')
    assert res_overview.status_code == 200
    data_overview = res_overview.get_json()
    assert 'total_scanned' in data_overview
    assert 'accuracy_rate' in data_overview

    res_trends = client.get('/api/v1/analytics/trends')
    assert res_trends.status_code == 200
    data_trends = res_trends.get_json()
    assert 'labels' in data_trends
    assert 'datasets' in data_trends

def test_apikeys_lifecycle(client):
    # Create key
    res_create = client.post('/api/v1/apikeys/', json={"name": "Test Automation Key"})
    assert res_create.status_code == 201
    key_data = res_create.get_json()
    assert "raw_key" in key_data
    raw_key = key_data["raw_key"]
    key_id = key_data["key_details"]["id"]

    # Use key in prediction header
    res_pred = client.post(
        '/api/v1/predict/text',
        json={"text": "Legitimate test message"},
        headers={"X-API-Key": raw_key}
    )
    assert res_pred.status_code == 200

    # List keys
    res_list = client.get('/api/v1/apikeys/')
    assert res_list.status_code == 200
    keys = res_list.get_json()
    assert len(keys) >= 1

    # Delete key
    res_del = client.delete(f'/api/v1/apikeys/{key_id}')
    assert res_del.status_code == 200

def test_settings_profile(client):
    res = client.get('/api/v1/settings/profile')
    assert res.status_code == 200
    
    update_res = client.put('/api/v1/settings/profile', json={"username": "superadmin", "notifications_enabled": False})
    assert update_res.status_code == 200
    assert update_res.get_json()["user"]["username"] == "superadmin"

def test_batch_prediction_large_payload(client):
    batch_payload = {
        "items": [
            {"type": "text", "content": "Priye grahak bijli kat di jayegi"},
            {"type": "url", "content": "https://parivahan.gov.in"},
            {"type": "url", "content": "http://echallan-traffic-pay.xyz"},
            {"type": "text", "content": "Quarterly sprint notes for tomorrow 10 AM meeting"}
        ]
    }
    res = client.post('/api/v1/predict/batch', json=batch_payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["total_processed"] == 4
    assert len(data["results"]) == 4
    assert "processing_time_ms" in data


def test_feed_risk_filter(client):
    res = client.get('/api/v1/feed/')
    assert res.status_code == 200
    feeds = res.get_json()
    assert len(feeds) > 0
    assert any(f.get('category') == 'Public Services' for f in feeds)

