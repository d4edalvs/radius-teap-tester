"""teap-tester — pure Python EAP-TEAP client for RADIUS authentication testing.

Public API:
    run_teap_test(...) -> TEAPResult
"""

import asyncio

from .types import TEAPTestConfig, TEAPResult, LogEntry
from .state_machine import TEAPSession

__all__ = ["run_teap_test", "TEAPTestConfig", "TEAPResult", "LogEntry", "TEAPSession"]

__version__ = "0.1.0"


async def run_teap_test(
    radius_host: str,
    radius_port: int,
    radius_secret: str,
    identity: str,
    outer_identity: str = "",
    password: str = "",
    machine_password: str = "",
    machine_identity: str = "",
    client_cert_pem: str = "",
    client_key_pem: str = "",
    machine_cert_pem: str = "",
    machine_key_pem: str = "",
    ca_chain_pem: str = "",
    source_ip: str = "",
    bind_ip: str = "",
    calling_station_id: str = "AA-BB-CC-DD-EE-FF",
    called_station_id: str = "",
    nas_port_type: int = 15,
    connect_info: str = "",
    nas_identifier: str = "",
    nas_port: int = 1,
    framed_mtu: int = 1500,
    retries: int = 3,
    extra_attrs: list[tuple[int, bytes]] | None = None,
    timeout: float = 30.0,
    exchange_timeout: float = 10.0,
) -> TEAPResult:
    config = TEAPTestConfig(
        radius_host=radius_host,
        radius_port=radius_port,
        radius_secret=radius_secret,
        identity=identity,
        outer_identity=outer_identity,
        password=password,
        machine_password=machine_password,
        machine_identity=machine_identity,
        client_cert_pem=client_cert_pem,
        client_key_pem=client_key_pem,
        machine_cert_pem=machine_cert_pem,
        machine_key_pem=machine_key_pem,
        ca_chain_pem=ca_chain_pem,
        source_ip=source_ip,
        bind_ip=bind_ip,
        calling_station_id=calling_station_id,
        called_station_id=called_station_id,
        nas_port_type=nas_port_type,
        connect_info=connect_info,
        nas_identifier=nas_identifier,
        nas_port=nas_port,
        framed_mtu=framed_mtu,
        retries=retries,
        extra_attrs=list(extra_attrs or []),
        timeout=timeout,
        exchange_timeout=exchange_timeout,
    )
    session = TEAPSession(config)
    try:
        return await asyncio.wait_for(session.run(), timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        return session.timeout_result(timeout)
