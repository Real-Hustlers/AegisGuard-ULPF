def map_system_activity(event: dict) -> dict:
    """
    Maps system/configuration events
    into OCSF System Activity.
    """


    return {

        "class_uid": 1001,

        "class_name": "System Activity",


        "activity_id": 1,


        "category_uid": 1,


        "time": event.get(
            "timestamp"
        ),


        "message": event.get(
            "reason"
        ),


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