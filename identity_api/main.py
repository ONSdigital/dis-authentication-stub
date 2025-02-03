from datetime import datetime, timezone
from typing import List, Optional, Dict

import uvicorn
from fastapi import FastAPI, Query, Path
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="dp-identity-api",
    description="An API used to manage the authorisation of groups accessing data publishing services.",
    version="1.0.0",
)

# Frozen time for test
FIXED_DATE = datetime(2024, 1, 1, 0, 0, 0).replace(tzinfo=timezone.utc).isoformat()

# Data Models
class ErrorObject(BaseModel):
    code: str = Field(
        ..., description="Code representing the type of error that occurred"
    )
    description: str = Field(..., description="Description of the error")


class ErrorResponse(BaseModel):
    errors: List[ErrorObject] = Field(..., description="A list of any errors")


class Group(BaseModel):
    id: str = Field(..., description="The group id")
    name: str = Field(..., description="The group name")
    precedence: int = Field(..., description="The priority of the group")
    created: str = Field(..., description="The date the group was created")


class GroupsList(BaseModel):
    groups: List[Group] = Field(
        ..., description="A list of groups for the response body"
    )
    count: int = Field(..., description="Number of groups")


# In-memory data store for groups
groups_db: Dict[str, Group] = {}

# Sample test data
def init_test_data():
    groups_db["role-admin"] = Group(
        id="role-admin",
        name="Administrators",
        precedence=2,
        created=FIXED_DATE,
    )
    groups_db["role-publisher"] = Group(
        id="role-publisher",
        name="Publishing Officers",
        precedence=3,
        created=FIXED_DATE,
    )
    groups_db["rsi-team"] = Group(
        id="rsi-team",
        name="RSI Preview Team",
        precedence=3,
        created=FIXED_DATE,
    )
    # Create additional dummy preview teams
    for i in range(1, 6):
        group_id = f"preview-team-{i}"
        groups_db[group_id] = Group(
            id=group_id,
            name=f"Preview Team {i}",
            precedence=4 + i,
            created=FIXED_DATE,
        )


init_test_data()

# Helper function for error responses
def error_response(status_code: int, code: str, description: str):
    return JSONResponse(
        status_code=status_code,
        content={"errors": [{"code": code, "description": description}]},
    )


@app.get("/groups", response_model=GroupsList)
def list_groups(
    sort: Optional[str] = Query(
        "created",
        description="Sort order",
        enum=["created", "name", "name:asc", "name:desc"],
    )
):
    groups = list(groups_db.values())
    reverse = sort.endswith(":desc")
    sort_key = sort.split(":")[0] if ":" in sort else sort
    sort_attr = {"created": "created", "name": "name"}.get(sort_key, "created")
    groups.sort(key=lambda x: getattr(x, sort_attr), reverse=reverse)
    return GroupsList(groups=groups, count=len(groups))


@app.get("/groups/{id}", response_model=GroupsList)
def get_group(id: str = Path(..., description="The group's ID")):
    group = groups_db.get(id)
    if not group:
        return error_response(400, "InvalidGroupID", "Invalid group name provided")
    return GroupsList(groups=[group], count=1)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
