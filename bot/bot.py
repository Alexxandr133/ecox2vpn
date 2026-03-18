import asyncio

from aiogram import Bot, Dispatcher
from aiogram.filters import CommandStart, Command
from aiogram.types import Message, ReplyKeyboardMarkup, KeyboardButton, WebAppInfo

BOT_TOKEN = "8763449387:AAHM023uMjJyoLOhSM_GLcMi1j9eFuNC4D8"
WEB_APP_URL = "https://ecox2vpn.online/"


async def main() -> None:
    if not BOT_TOKEN:
        raise RuntimeError("Укажи токен бота в BOT_TOKEN")

    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher()

    @dp.message(CommandStart())
    async def cmd_start(message: Message) -> None:
        keyboard = ReplyKeyboardMarkup(
            keyboard=[
                [
                    KeyboardButton(
                        text="Открыть VPN панель",
                        web_app=WebAppInfo(url=WEB_APP_URL),
                    )
                ]
            ],
            resize_keyboard=True,
            one_time_keyboard=False,
        )
        await message.answer(
            "Привет! Нажми кнопку ниже, чтобы открыть веб‑панель VPN.",
            reply_markup=keyboard,
        )

    @dp.message(Command("app"))
    async def cmd_app(message: Message) -> None:
        await message.answer(f"Веб‑панель доступна по адресу:\n{WEB_APP_URL}")

    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())

