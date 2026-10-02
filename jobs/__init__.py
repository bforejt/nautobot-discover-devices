"""Jobs entry point for Nautobot Git datasource and local Jobs packages."""

from nautobot.apps.jobs import register_jobs

from .discovery_job import DiscoverDevice

register_jobs(DiscoverDevice)
