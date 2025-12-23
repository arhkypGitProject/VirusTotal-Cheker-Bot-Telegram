from aiogram.fsm.state import State, StatesGroup

class IPScan(StatesGroup):
    waiting_for_ip = State()

class URLScan(StatesGroup):
    waiting_for_url = State()

class DOMAINScan(StatesGroup):
    waiting_for_domain = State()

class FILEScan(StatesGroup):
    waiting_for_file = State()

class URLandFILEScan(StatesGroup):
    waiting_for_id = State()
