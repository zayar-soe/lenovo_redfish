#!/usr/bin/env python3
import sys
import json
import traceback
import redfish
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_firmware_update(ip, username, password):
    """Check Lenovo BMC for available firmware versions."""
    base_url = f"https://{ip}"
    result = {}

    try:
        rf = redfish.redfish_client(
            base_url=base_url,
            username=username,
            password=password,
            default_prefix="/redfish/v1",
            timeout=30,
            cafile=False
        )
        rf.login()
    except Exception:
        traceback.print_exc()
        return {"ret": False, "msg": "Login failed - check IP/username/password"}

    try:
        # Get UpdateService
        update_service_resp = rf.get("/redfish/v1/UpdateService")
        if update_service_resp.status != 200:
            return {"ret": False, "msg": f"Failed to get UpdateService: {update_service_resp.status}"}

        # Check FirmwareInventory
        if "FirmwareInventory" in update_service_resp.dict:
            fw_url = update_service_resp.dict["FirmwareInventory"]["@odata.id"]
        else:
            return {"ret": False, "msg": "No FirmwareInventory found"}

        fw_resp = rf.get(fw_url)
        if fw_resp.status != 200:
            return {"ret": False, "msg": f"Failed to get FirmwareInventory: {fw_resp.status}"}

        available_updates = []
        for item in fw_resp.dict.get("Members", []):
            member_url = item["@odata.id"]
            member_resp = rf.get(member_url)
            if member_resp.status == 200:
                name = member_resp.dict.get("Name", "Unknown")
                version = member_resp.dict.get("Version", "Unknown")
                status = member_resp.dict.get("Status", {}).get("State", "Unknown")
                available_updates.append({
                    "Name": name,
                    "Version": version,
                    "State": status
                })

        result = {"ret": True, "available_updates": available_updates}
    except Exception as e:
        traceback.print_exc()
        result = {"ret": False, "msg": str(e)}
    finally:
        try:
            rf.logout()
        except:
            pass

    return result


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <BMC_IP> <USER> <PASSWORD>")
        sys.exit(1)

    ip, user, pwd = sys.argv[1], sys.argv[2], sys.argv[3]
    res = check_firmware_update(ip, user, pwd)
    if res["ret"]:
        print(json.dumps(res["available_updates"], indent=2))
    else:
        sys.stderr.write(res["msg"] + "\n")
        sys.exit(1)
