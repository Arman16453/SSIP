"""Fix notification relationships

Revision ID: d48ad4ff3018
Revises: c992206695ae
Create Date: 2025-04-08 15:26:42.613210

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd48ad4ff3018'
down_revision = 'c992206695ae'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('application', schema=None) as batch_op:
        batch_op.alter_column('team_members',
               existing_type=sa.TEXT(),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('application', schema=None) as batch_op:
        batch_op.alter_column('team_members',
               existing_type=sa.TEXT(),
               nullable=False)

    # ### end Alembic commands ###
