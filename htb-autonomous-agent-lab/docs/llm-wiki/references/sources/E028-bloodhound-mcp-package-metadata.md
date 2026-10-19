<!-- source: https://github.com/mwnickerson/bloodhound_mcp/blob/cdb17097e761c8a8622cb93bc3ba49a9e150bb6e/pyproject.toml
     fetched_from: https://raw.githubusercontent.com/mwnickerson/bloodhound_mcp/cdb17097e761c8a8622cb93bc3ba49a9e150bb6e/pyproject.toml
     retrieved: 2026-10-19
     raw_sha256: 7e6214e5d83471140b0d3f18a090dabc1aaa15f250fca95d7afad38baf91c2ee
     note: text extraction of the original page; formatting simplified -->

[project]
name = "bloodhound-mcp"
version = "0.1.0"
description = "MCP for Connecting Claude Desktop to Bloodhound CE"
readme = "README.md"
requires-python = ">=3.11"
dependencies = [
    "mcp==1.9.4",
    "python-dotenv==1.1.1",
    "requests==2.32.4",
]

[project.scripts]
bloodhound-mcp = "main:main"

[build-system]
requires = ["setuptools>=77"]
build-backend = "setuptools.build_meta"

[tool.setuptools]
py-modules = ["main"]

[tool.setuptools.packages.find]
include = ["lib*"]
namespaces = true

[dependency-groups]
dev = [
    "black>=25.1.0",
    "pytest>=8.3.5",
    "pytest-cov>=6.1.1",
    "pytest-mock>=3.14.1",
    "requests-mock>=1.12.1",
    "responses>=0.25.7",
]
