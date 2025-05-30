from typing import Callable, Any, List
from flask import Flask, Response, render_template, url_for, make_response
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
    routes: List[Any] = []

    for rule in app.url_map.iter_rules():
        # Exclude rules that require parameters and rules you can't open in a browser
        if rule.methods is not None and "GET" in rule.methods and has_no_empty_params(rule):
            url: str = url_for(rule.endpoint, **(rule.defaults or {}))
            routes.append(url)
    print("\n".join(map(lambda url: f"http://localhost:5000{url}", routes)))
    return render_template(template_name_or_list="main.j2", routes=routes)

# X-Content-Type-Options

@app.route("/x_content_type_options_header_value_is_not_nosniff")
@with_security_headers(**{
    "X-Content-Type-Options": "-1",
    "Content-Security-Policy": "default-src 'self' object-src 'none'",
    "X-Frame-Options": "DENY",
})
def x_content_type_options_header_value_is_not_nosniff() -> str:
    return "x_content_type_options_header_value_is_not_nosniff"

@app.route("/x_content_type_options_header_is_missing")
@with_security_headers(**{
    "Content-Security-Policy": "default-src 'self' object-src 'none'",
    "X-Frame-Options": "DENY",
})
def x_content_type_options_header_is_missing() -> str:
    return "x_content_type_options_header_is_missing"

# X-Frame-Options

# Set to DENY
# Not a valid slug/finding, this route is used to check for false positives
@app.route("/x_frame_options_is_set_to_deny")
@with_security_headers(**{
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self' object-src 'none'",
    "X-Frame-Options": "DENY",
})
def x_frame_options_is_set_to_deny() -> str:
    return "x_frame_options_is_set_to_deny"

# Set to SAMEORIGIN
@app.route("/x_frame_options_is_set_to_sameorigin")
@with_security_headers(**{
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self' object-src 'none'",
    "X-Frame-Options": "SAMEORIGIN",
})
def x_frame_options_is_set_to_sameorigin() -> str:
    return "x_frame_options_is_set_to_sameorigin"

# Not set
@app.route("/x_frame_options_is_not_set")
@with_security_headers(**{
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self' object-src 'none'",
})
def x_frame_options_is_not_set() -> str:
    return "x_frame_options_is_not_set"

# Content-Security-Policy

# csp_header_script_src_unsafe_inline
@app.route("/csp_header_script_src_unsafe_inline")
@with_security_headers(**{
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; object-src 'none'",
    "X-Frame-Options": "DENY",
})
def csp_header_script_src_unsafe_inline() -> str:
    return "csp_header_script_src_unsafe_inline"

# csp_header_script_src_unsafe_eval
@app.route("/csp_header_script_src_unsafe_eval")
@with_security_headers(**{
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-eval'; object-src 'none'",
    "X-Frame-Options": "DENY",
})
def csp_header_script_src_unsafe_eval() -> str:
    return "csp_header_script_src_unsafe_eval"

# csp_header_object_source_not_none
@app.route("/csp_header_object_source_not_none")
@with_security_headers(**{
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; object-src 'https://www.google.com'", # Google is a JSONP enpoint
    "X-Frame-Options": "DENY",
})
def csp_header_object_source_not_none() -> str:
    return "csp_header_object_source_not_none"

# csp_header_is_not_set
@app.route("/csp_header_is_not_set")
@with_security_headers(**{
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
})
def csp_header_is_not_set() -> str:
    return "csp_header_is_not_set"

if __name__ == '__main__':
    app.run(debug=True)