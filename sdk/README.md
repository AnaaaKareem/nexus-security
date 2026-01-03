# DevSecOps SDK

This folder contains the **client-side SDK** and **API contracts** for the DevSecOps microservices.
It is intended to be installed as a library by other services in the future to fully decouple them from the `services/common` shared library.

## Purpose

Currently, our services share `services/common` which contains direct Database Models (SQLAlchemy). This creates a dependency where every service needs to know about the Database.

This SDK solves that by providing **Pydantic Schemas** (Pure Data Classes) that define the "Shape" of the data sent over the API, without any database logic attached.

## Structure

- `schemas.py`: Request/Response objects (e.g. `ScanRequest`, `FindingSchema`)
- `client.py`: (Future) A Python wrapper class to call the APIs easily.

## Usage (Future State)

Instead of:

```python
from common.core.models import Scan
```

Services will do:

```python
from devsecops_sdk.schemas import ScanModel
```
