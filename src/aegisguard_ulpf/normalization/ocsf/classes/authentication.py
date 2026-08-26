def map_authentication(
    event: dict,
) -> dict:
    """
    Maps authentication related events
    into OCSF Authentication Activity.
    """

    return {

        "class_uid": 3002,

        "class_name": "Authentication",

        "activity": (
            event.get(
                "type"
            )
            or "login"
        ),


        "time": event.get(
            "timestamp"
        ),


        "user": {

            "name": event.get(
                "user"
            )

        },


        "src_endpoint": {

            "ip": event.get(
                "src_ip"
            )

        },


        "status": {

            "result": event.get(
                "outcome"
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