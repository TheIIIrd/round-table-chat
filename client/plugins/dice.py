"""
Игровой плагин: кубики, монетка, выбор.
"""

import random
from client.plugins.base import PluginBase, PluginAPI


class DicePlugin(PluginBase):
    name = "dice"
    commands = {
        "/roll":   "Roll dice: /roll [count]d[sides] (default 1d6)",
        "/flip":   "Flip a coin",
        "/choose": "Choose from options: /choose pizza sushi burger",
    }

    def __init__(self, api: PluginAPI):
        super().__init__(api)

    async def handle_command(self, command: str, args: str) -> bool:
        if command == "/roll":
            await self._roll(args)
            return True
        elif command == "/flip":
            await self._flip()
            return True
        elif command == "/choose":
            await self._choose(args)
            return True
        return False

    async def _roll(self, args: str) -> None:
        parts = args.strip().split('d') if args.strip() else ['1', '6']
        try:
            count = int(parts[0]) if parts[0] else 1
            sides = int(parts[1]) if len(parts) > 1 else 6
        except ValueError:
            self.api.send_system("[dice] Usage: /roll [count]d[sides]  Example: /roll 2d20")
            return

        count = min(count, 100)
        sides = min(sides, 1000)

        rolls = [random.randint(1, sides) for _ in range(count)]
        result = ' + '.join(str(r) for r in rolls)
        if len(rolls) > 1:
            result += f' = {sum(rolls)}'

        nick = self.api.my_nickname
        await self.api.send_chat(f"{nick} rolled {count}d{sides}: {result}")

    async def _flip(self) -> None:
        result = random.choice(['heads', 'tails'])
        nick = self.api.my_nickname
        await self.api.send_chat(f"{nick} flipped: {result}")

    async def _choose(self, args: str) -> None:
        options = [o.strip() for o in args.split() if o.strip()]
        if len(options) < 2:
            self.api.send_system("[dice] Usage: /choose option1 option2 ...")
            return
        choice = random.choice(options)
        nick = self.api.my_nickname
        await self.api.send_chat(f"{nick} chooses: {choice}")
