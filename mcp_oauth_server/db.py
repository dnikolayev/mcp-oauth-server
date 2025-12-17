from __future__ import annotations

import logging
from typing import AsyncGenerator

from sqlalchemy import Column, String, Text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

logger = logging.getLogger(__name__)

Base = declarative_base()


class StoreItem(Base):
    """Generic Key-Value store table."""

    __tablename__ = "mcp_store"

    key = Column(String(255), primary_key=True)
    value = Column(Text, nullable=False)


class Database:
    def __init__(self, database_url: str) -> None:
        self.engine = create_async_engine(database_url, echo=False)
        self.session_maker = async_sessionmaker(self.engine, expire_on_commit=False)

    async def init_db(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        async with self.session_maker() as session:
            yield session

    async def close(self) -> None:
        await self.engine.dispose()
