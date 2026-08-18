import urllib.request, json
try:
    data = json.dumps({"username":"admin","password":"dfim_admin_2026"}).encode()
    req = urllib.request.Request("http://localhost:3000/v1/auth/login", data=data, headers={"Content-Type":"application/json"}, method="POST")
    r = urllib.request.urlopen(req, timeout=5)
    resp = json.loads(r.read())
    token = resp.get("access_token","")
    print(f"Login: {r.status} | token={'OK' if token else 'FAIL'}")
    
    if token:
        req2 = urllib.request.Request("http://localhost:3000/v1/fleet/summary", headers={"Authorization":f"Bearer {token}"})
        r2 = urllib.request.urlopen(req2, timeout=5)
        fleet = json.loads(r2.read())
        print(f"Fleet: {fleet['total_assets']} assets | {fleet['healthy']} healthy | {fleet['tampered']} tampered")
except Exception as e:
    print(f"Error: {e}")
