from typing import Callable, Any
from flask import Flask, Response, url_for, make_response
from functools import wraps

# https://pypi.org/project/flask-talisman/

app = Flask(__name__)

def has_no_empty_params(rule):
    defaults = rule.defaults if rule.defaults is not None else ()
    arguments = rule.arguments if rule.arguments is not None else ()

    return len(defaults) >= len(arguments)


# Custom decorator for security headers
# From claude
def with_security_headers(**headers) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(f) -> Callable[..., Any]:
        @wraps(wrapped=f)
        def decorated_function(*args, **kwargs) -> Response:
            response: Response = make_response(f(*args, **kwargs))
            for header, value in headers.items():
                response.headers[header] = value
            return response
        return decorated_function
    return decorator

@app.route('/')
def main():
    # From: https://bobbyhadz.com/blog/get-list-of-all-routes-defined-in-flask-application
    routes = []

    for rule in app.url_map.iter_rules():
        # Exclude rules that require parameters and rules you can't open in a browser
        if rule.methods is not None and "GET" in rule.methods and has_no_empty_params(rule):
            url = url_for(rule.endpoint, **(rule.defaults or {}))
            routes.append((url, rule.endpoint))

    print(routes)
    return routes

if __name__ == '__main__':
    app.run(debug=True)