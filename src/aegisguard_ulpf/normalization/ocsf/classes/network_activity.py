def map_network_activity(event: dict) -> dict:
    """
    Maps firewall/router traffic logs
    into OCSF Network Activity class.
    """


    action = event.get(
        "action"
    )


    disposition_map = {

        "allow": "Allowed",

        "deny": "Blocked",

        "drop": "Blocked",

    }


    return {

        "class_uid": 4001,

        "class_name": "Network Activity",


        "activity_id": 1,
	"activity": event.get(
    "type"),


        "category_uid": 4,

        "category_name": "Network Activity",


        "time": event.get(
            "timestamp"
        ),


        "severity": event.get(
            "severity"
        ),


        "disposition": disposition_map.get(
            action,
            "Unknown"
        ),


        "src_endpoint": {

            "ip": event.get(
                "src_ip"
            )

        },


        "dst_endpoint": {

            "ip": event.get(
                "dst_ip"
            )

        },


        "network": {

            "protocol": event.get(
                "protocol"
            )

        },


        "metadata": {

            "vendor":
                event.get("vendor"),

            "product":
                event.get("product"),

        },


        "raw_data": {
    "u_id": event.get("u_id"),
    "raw_id": event.get("raw_id"),
},
}