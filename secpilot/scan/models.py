from uuid import uuid4

from pydantic import BaseModel, Field

from secpilot.core.models import (
    HttpRequest,
)


class ScanTask(BaseModel):
    """
    扫描任务单元。

    一次批量扫描由多个 ScanTask 组成，
    每个 ScanTask 对应一个待测试请求。

    id:
        任务唯一标识。

        会同步写入对应的
        ScanRequestResult.request_id，
        用于结果与任务的对账。
    """

    id: str = Field(
        default_factory=lambda: uuid4().hex
    )

    request: HttpRequest
