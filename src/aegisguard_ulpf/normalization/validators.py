from aegisguard_ulpf.core.models import CommonEvent


def _require_non_empty_text(
    value: str,
    *,
    field_name: str,
) -> None:
    if not value.strip():
        raise ValueError(
            f"{field_name} must not be empty or whitespace"
        )


def _validate_port(
    value: int | None,
    *,
    field_name: str,
) -> None:
    if value is not None and not 0 <= value <= 65535:
        raise ValueError(
            f"{field_name} must be between 0 and 65535"
        )


def _validate_non_negative(
    value: int | None,
    *,
    field_name: str,
) -> None:
    if value is not None and value < 0:
        raise ValueError(
            f"{field_name} must be greater than or equal to 0"
        )


def validate_common_event(
    event: CommonEvent,
) -> CommonEvent:
    _require_non_empty_text(
        event.traceability.u_id,
        field_name="traceability.u_id",
    )
    _require_non_empty_text(
        event.traceability.raw_id,
        field_name="traceability.raw_id",
    )
    _require_non_empty_text(
        event.vendor.vendor,
        field_name="vendor.vendor",
    )
    _require_non_empty_text(
        event.vendor.product,
        field_name="vendor.product",
    )

    if event.src_endpoint is not None:
        _validate_port(
            event.src_endpoint.port,
            field_name="src_endpoint.port",
        )

    if event.dst_endpoint is not None:
        _validate_port(
            event.dst_endpoint.port,
            field_name="dst_endpoint.port",
        )

    if event.nat is not None:
        _validate_port(
            event.nat.translated_src_port,
            field_name="nat.translated_src_port",
        )
        _validate_port(
            event.nat.translated_dst_port,
            field_name="nat.translated_dst_port",
        )

    if event.network is not None:
        numeric_fields = {
            "bytes_in": event.network.bytes_in,
            "bytes_out": event.network.bytes_out,
            "bytes_total": event.network.bytes_total,
            "packets_in": event.network.packets_in,
            "packets_out": event.network.packets_out,
            "packets_total": event.network.packets_total,
            "duration_seconds": event.network.duration_seconds,
        }

        for field_name, value in numeric_fields.items():
            _validate_non_negative(
                value,
                field_name=f"network.{field_name}",
            )

    try:
        processed_before_observed = (
            event.timestamps.processed_time
            < event.timestamps.observed_time
        )
    except TypeError as error:
        raise ValueError(
            "timestamps.processed_time and "
            "timestamps.observed_time must be comparable"
        ) from error

    if processed_before_observed:
        raise ValueError(
            "timestamps.processed_time must not be earlier "
            "than timestamps.observed_time"
        )

    return event
