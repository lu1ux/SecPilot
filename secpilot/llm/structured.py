import json
from typing import TypeVar

from pydantic import (
    BaseModel,
    ValidationError,
)


StructuredModel = TypeVar(
    "StructuredModel",
    bound=BaseModel,
)


class StructuredOutputError(
    ValueError
):
    """
    无法从模型输出中提取
    合法结构化数据时抛出。
    """

    pass


def build_structured_prompt(
    output_model: type[
        StructuredModel
    ],
) -> str:
    """
    为不支持原生 Structured Output
    的模型生成 JSON 输出约束。

    即便模型只支持普通文本生成，
    也可以使用这种方式。
    """

    schema = (
        output_model
        .model_json_schema()
    )

    schema_text = json.dumps(
        schema,
        ensure_ascii=False,
        indent=2,
    )

    return (
        "\n\n"
        "You must return exactly one JSON object.\n"
        "Do not use Markdown code fences.\n"
        "Do not include explanations before or after the JSON.\n"
        "The JSON must satisfy this JSON Schema:\n"
        f"{schema_text}"
    )


def extract_json_object(
    text: str,
) -> dict:
    """
    从模型输出中提取 JSON Object。

    支持：

    1. 纯 JSON
    2. ```json ... ```
    3. JSON 前后夹杂少量文本

    最终仍然需要 Pydantic 校验。
    """

    candidate = text.strip()

    if candidate.startswith(
        "```"
    ):
        lines = (
            candidate
            .splitlines()
        )

        if lines:
            lines = lines[1:]

        if (
            lines
            and lines[-1]
            .strip()
            .startswith("```")
        ):
            lines = lines[:-1]

        candidate = (
            "\n".join(
                lines
            )
            .strip()
        )

    try:

        value = json.loads(
            candidate
        )

        if not isinstance(
            value,
            dict,
        ):
            raise (
                StructuredOutputError(
                    "模型输出 JSON "
                    "不是 Object"
                )
            )

        return value

    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()

    for index, character in enumerate(
        candidate
    ):

        if character != "{":
            continue

        try:

            value, _ = (
                decoder.raw_decode(
                    candidate[
                        index:
                    ]
                )
            )

        except json.JSONDecodeError:
            continue

        if isinstance(
            value,
            dict,
        ):
            return value

    raise StructuredOutputError(
        "无法从模型输出中提取 JSON Object"
    )


def validate_structured_output(
    text: str,
    output_model: type[
        StructuredModel
    ],
) -> StructuredModel:
    """
    JSON 提取 + Pydantic 校验。
    """

    data = extract_json_object(
        text
    )

    try:

        return (
            output_model
            .model_validate(
                data
            )
        )

    except ValidationError as exc:

        raise StructuredOutputError(
            "模型 JSON 没有通过 "
            "Pydantic Schema 校验"
        ) from exc