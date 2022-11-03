# import logging
#
# from typing import List
#
# from sqlalchemy.future import select
# from sqlalchemy.orm import joinedload
# from fastapi import status, HTTPException
#
# from .. import (
#     models,
#     tables,
# )
# from .base_service import BaseService
#
# logger = logging.getLogger(__name__)
#
#
# class UsersService(BaseService):
#
#     async def create_user_profile_stats(self, user_data: models.UserCreate) -> tables.User:
#         user = await self.create(table=tables.User,
#                                  data=user_data.dict())
#
#         await self.create(table=tables.UserProfile, data={'user_id': user.id})
#         await self.create(table=tables.UserStats, data={'user_id': user.id})
#         return user
#
#     async def get_user_with_stats_and_profile(self, table: tables.Base, wanted, column) -> object:
#         logger.debug('get_or_404')
#
#         result = await self.session.execute(select(table)
#                                             .where(column == wanted)
#                                             .options(joinedload(table.profile), joinedload(table.stats)))
#         entry = result.scalar()
#
#         if not entry:
#             logger.warning(f'entry not found: {wanted}, table: {table}, column: {column}')
#             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
#
#         logger.info(f'Got entity id: {entry.id}')
#
#         return entry
#
#     async def get_many_users_groups_by_user_telegram_id(self, telegram_id: int) -> List[tables.UsersGroups]:
#         logger.debug('get_user_with_groups_by_telegram_id: %s', telegram_id)
#         result = await self.session.execute(
#             select(tables.User).where(tables.User.telegram_id == telegram_id)
#             .options(joinedload(tables.User.groups).joinedload(tables.UsersGroups.group))
#         )
#         user_joined = result.scalar()
#         return user_joined.groups
#
#     async def get_one_users_group_by_user_id(
#             self,
#             user_id: int,
#             group_id: int
#     ) -> tables.UsersGroups:
#
#         logger.debug('get_one_users_group_by_user_id: %s, group_id: %s', user_id, group_id)
#         result = await self.session.execute(
#             select(tables.UsersGroups)
#             .where(tables.UsersGroups.user_id == user_id, tables.UsersGroups.group_id == group_id)
#             .options(joinedload(tables.UsersGroups.group).joinedload(tables.Group.payment_variants))
#         )
#         user_group = result.scalar()
#
#         if not user_group:
#             logger.warning('UserGroup not found! User id: %s -- Group_id: %s', user_id, group_id)
#             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User probably not in group')
#
#         return user_group
