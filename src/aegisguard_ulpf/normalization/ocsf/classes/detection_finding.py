def map_detection_finding(
    event: dict,
) -> dict:
    """
    Maps security alerts and threat events
    into OCSF Detection Finding.
    """


    return {

        "class_uid": 2004,

        "class_name": "Detection Finding",


        "time": event.get(
            "timestamp"
        ),


        "severity": event.get(
            "severity"
        ),


        "finding": {

            "title": event.get(
                "type"
            ),

            "description": event.get(
                "details"
            )

        },


        "threat": {

            "category": event.get(
                "category"
            ),

            "name": event.get(
                "subtype"
            )

        },


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


        "metadata": {

            "vendor": event.get(
                "vendor"
            ),

            "product": event.get(
                "product"
            )

        },


        "raw_data": {

            "u_id": event.get(
                "u_id"
            ),

            "raw_id": event.get(
                "raw_id"
            )

        }

    }