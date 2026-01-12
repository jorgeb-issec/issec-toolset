
import sys
import os

# Ensure app is in path
sys.path.append(os.getcwd())

try:
    from app import create_app
    app = create_app()
    
    print("App created successfully.")
    
    # Check Blueprints
    blueprints = app.blueprints.keys()
    print(f"Registered Blueprints: {list(blueprints)}")
    
    if 'log_analytics' in blueprints and 'api_v1' in blueprints:
        print("Required blueprints Found.")
    else:
        print("MISSING blueprints!")
        exit(1)

    # Check Routes
    found_logs_view = False
    found_logs_api = False
    
    for rule in app.url_map.iter_rules():
        if str(rule).startswith('/analyzer'):
            found_logs_view = True
        # API might also be /analyzer or /api/v1/analyzer
        if str(rule).startswith('/api/v1/log_analyzer') or str(rule).startswith('/analyzer'):
             found_logs_api = True # simplified check since analyzer uses same route for both with method dispatch
            
    if found_logs_view:
        print("Routes Confirmed: /analyzer")
    else:
        print(f"Missing Routes. View: {found_logs_view}, API: {found_logs_api}")
        # Print all for debug
        # for rule in app.url_map.iter_rules(): print(rule)
        exit(1)

except Exception as e:
    print(f"CRITICAL ERROR: {e}")
    import traceback
    traceback.print_exc()
    exit(1)
