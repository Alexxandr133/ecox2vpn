import asyncio
import os

from aiogram import Bot, Dispatcher
from aiogram.filters import CommandStart, Command
from aiogram.types import Message


BOT_TOKEN = "8763449387:AAHM023uMjJyoLOhSM_GLcMi1j9eFuNC4D8"
WEB_APP_URL = "http://127.0.0.1:8000/"


async def main() -> None:
    if not BOT_TOKEN:
        raise RuntimeError("Укажи токен бота в BOT_TOKEN")

    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher()

    @dp.message(CommandStart())
    async def cmd_start(message: Message) -> None:
        await message.answer(
            "Привет! Я VPN‑бот.\n\n"
            "• Команда /app — показать ссылку на локальную веб‑панель.\n"
            "• Позже здесь появится выдача ключей VLESS/VMess."
        )

    @dp.message(Command("app"))
    async def cmd_app(message: Message) -> None:
        await message.answer(f"Локальная веб‑панель сейчас доступна по адресу:\n{WEB_APP_URL}")

    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())

