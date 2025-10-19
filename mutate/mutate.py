# superclass that is a template for other mutations
# contains: mutate(), internal storage, run()
from pydantic import BaseModel, Field


class Mutation(BaseModel):
    name: str
