import json
import random
import time
from web3 import Web3

from fake_useragent import UserAgent
from loguru import logger
from eth_account.messages import encode_defunct
import asyncio
import aiohttp
from web3.eth import AsyncEth

from info import *
from config import *
from eth_utils import *
from moralis import evm_api


class Help:
    async def check_status_tx(self, tx_hash, ):
        logger.info(
            f'{self.address} - жду подтверждения транзакции {scans[self.chain]}{self.w3.to_hex(tx_hash)}...')

        start_time = int(time.time())
        while True:
            current_time = int(time.time())
            if current_time >= start_time + 150:
                logger.info(
                    f'{self.address} - транзакция не подтвердилась за 150 cекунд, начинаю повторную отправку...')
                return 0
            try:
                status = (await self.w3.eth.get_transaction_receipt(tx_hash))['status']
                if status == 1:
                    return status
                await asyncio.sleep(1)
            except Exception as error:
                await asyncio.sleep(1)

    async def sleep_indicator(self, secs):
        logger.info(f'{self.address} - жду {secs} секунд...')
        await asyncio.sleep(secs)


class ZkBridge(Help):
    def __init__(self, privatekey, delay, chain, to, api, proxy=None):
        self.privatekey = privatekey
        self.chain = chain
        self.to = random.choice(to) if type(to) == list else to
        self.w3 = Web3(Web3.AsyncHTTPProvider(rpcs[self.chain]),
                       modules={'eth': (AsyncEth,)}, middlewares=[])
        self.account = self.w3.eth.account.from_key(self.privatekey)
        self.address = self.account.address
        self.nft = random.choice(nft) if type(nft) == list else nft
        self.delay = delay
        self.proxy = f'http://{proxy}' if proxy else None
        self.moralisapi = api
        self.nft_address = nfts_addresses[self.nft][self.chain]
        self.bridge_address = nft_lz_bridge_addresses[
            self.chain] if self.nft == 'Pandra' and self.to not in ('combo', 'taiko') else nft_bridge_addresses[self.chain]

    async def auth(self):
        ua = UserAgent()
        ua = ua.random
        headers = {
            'authority': 'api.zkbridge.com',
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'content-type': 'application/json',
            'origin': 'https://zkbridge.com',
            'referer': 'https://zkbridge.com/',
            'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': ua,
        }

        json_data = {
            'publicKey': self.address.lower(),
        }
        while True:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post('https://api.zkbridge.com/api/signin/validation_message',
                                            json=json_data, headers=headers, proxy=self.proxy) as response:
                        if response.status == 200:
                            msg = json.loads(await response.text())
                            msg = msg['message']
                            msg = encode_defunct(text=msg)
                            sign = self.w3.eth.account.sign_message(msg, private_key=self.privatekey)
                            signature = self.w3.to_hex(sign.signature)
                            json_data = {
                                'publicKey': self.address,
                                'signedMessage': signature,
                            }
                            return signature, ua
            except Exception as e:
                logger.error(f'{self.address}:{self.chain} - {e}')
                await asyncio.sleep(5)

    async def sign(self):
        # sign msg
        signature, ua = await self.auth()
        headers = {
            'authority': 'api.zkbridge.com',
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'content-type': 'application/json',
            'origin': 'https://zkbridge.com',
            'referer': 'https://zkbridge.com/',
            'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': ua,
        }

        json_data = {
            'publicKey': self.address.lower(),
            'signedMessage': signature,
        }
        while True:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post('https://api.zkbridge.com/api/signin',
                                            json=json_data, headers=headers, proxy=self.proxy) as response:
                        if response.status == 200:
                            token = (json.loads(await response.text()))['token']
                            headers['authorization'] = f'Bearer {token}'
                            return headers

            except Exception as e:
                logger.error(F'{self.address}:{self.chain} - {e}')
                await asyncio.sleep(5)

    async def profile(self):
        headers = await self.sign()
        params = ''
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api.zkbridge.com/api/user/profile',
                                       params=params, headers=headers, proxy=self.proxy) as response:
                    if response.status == 200:
                        logger.success(f'{self.address}:{self.chain} - успешно авторизовался...')
                        return headers
        except Exception as e:
            logger.error(f'{self.address}:{self.chain} - {e}')
            return False

    async def balance_and_get_id(self):
        if self.chain not in ['core', 'celo']:
            try:
                api_key = self.moralisapi
                params = {
                    "chain": self.chain,
                    "format": "decimal",
                    "token_addresses": [
                        self.nft_address
                    ],
                    "media_items": False,
                    "address": self.address}

                result = evm_api.nft.get_wallet_nfts(api_key=api_key, params=params)
                id_ = int(result['result'][0]['token_id'])
                if id_:
                    logger.success(f'{self.address}:{self.chain} - успешно найдена {self.nft} {id_}...')
                    return id_
            except Exception as e:
                if 'list index out of range' in str(e):
                    logger.error(f'{self.address}:{self.chain} - на кошельке отсутсвует {self.nft}...')
                    return None
                else:
                    logger.error(f'{self.address}:{self.chain} - {e}...')
        else:
            try:
                contract = self.w3.eth.contract(address=self.nft_address, abi=zk_nft_abi)
                balance = await contract.functions.balanceOf(self.address).call()
                if balance > 0:
                    totalSupply = await contract.functions.totalSupply().call()
                    id_ = \
                        (await contract.functions.tokensOfOwnerIn(self.address, totalSupply - 500, totalSupply).call())[
                            0]
                    return id_
                else:
                    logger.error(f'{self.address}:{self.chain} - на кошельке отсутсвует {self.nft}...')
                    return None
            except Exception as e:
                logger.error(f'{self.address}:{self.chain} - {e}...')
                await asyncio.sleep(1)

    async def mint(self):
        while True:
            zkNft = self.w3.eth.contract(address=Web3.to_checksum_address(self.nft_address), abi=zk_nft_abi)
            headers = await self.profile()
            if not headers:
                return False
            try:
                if headers:
                    nonce = await self.w3.eth.get_transaction_count(self.address)
                    await asyncio.sleep(2)
                    tx = await zkNft.functions.mint().build_transaction({
                        'from': self.address,
                        'gas': await zkNft.functions.mint().estimate_gas(
                            {'from': self.address, 'nonce': nonce}),
                        'nonce': nonce,
                        'maxFeePerGas': int(await self.w3.eth.gas_price),
                        'maxPriorityFeePerGas': int((await self.w3.eth.gas_price) * 0.8)
                    })
                    if self.chain == 'bsc' or self.chain == 'core':
                        del tx['maxFeePerGas']
                        del tx['maxPriorityFeePerGas']
                        tx['gasPrice'] = await self.w3.eth.gas_price

                    logger.info(f'{self.address}:{self.chain} - начинаю минт {self.nft}...')
                    sign = self.account.sign_transaction(tx)
                    hash = await self.w3.eth.send_raw_transaction(sign.rawTransaction)
                    status = await self.check_status_tx(hash)
                    if status == 1:
                        logger.success(
                            f'{self.address}:{self.chain} - успешно заминтил {self.nft} : {scans[self.chain]}{self.w3.to_hex(hash)}...')
                        await self.sleep_indicator(random.randint(self.delay[0], self.delay[1]))
                        return headers
                    else:
                        logger.info(f'{self.address}:{self.chain} - пробую минт еще раз...')
                        await self.mint()
            except Exception as e:
                error = str(e)
                if 'nonce too low' in error or 'already known' in error:
                    logger.success(f'{self.address}:{self.chain} - ошибка при минте, пробую еще раз...')
                    await asyncio.sleep(10)
                    await self.mint()
                if 'INTERNAL_ERROR: insufficient funds' in error or 'insufficient funds for gas * price + value' in error:
                    logger.error(
                        f'{self.address}:{self.chain} - не хватает денег на газ, заканчиваю работу через 5 секунд...')
                    await asyncio.sleep(5)
                    return False
                elif 'Each address may claim one NFT only. You have claimed already' in error:
                    logger.error(f'{self.address}:{self.chain} - {self.nft} можно клеймить только один раз!...')
                    return False
                else:
                    logger.error(f'{self.address}:{self.chain} - {e}...')
                    return False

    async def bridge_nft(self):
        time_ = random.randint(start_delay[0], start_delay[1])
        logger.info(f'Начинаю работу через {time_} cекунд...')
        await asyncio.sleep(time_)
        id_ = await self.balance_and_get_id()
        headers = await self.profile()
        if headers:
            headers = headers

        if id_ == None:
            headers = await self.mint()
            if headers:
                await asyncio.sleep(5)
                id_ = await self.balance_and_get_id()
                if not id_:
                    return self.privatekey, self.address, f'not {self.nft} on wallet'
            else:
                return self.privatekey, self.address, f'error {self.nft}'

        if self.nft == 'greenfield':
            return self.privatekey, self.address, f'succesfully minted greenfield'

        zkNft = self.w3.eth.contract(address=Web3.to_checksum_address(self.nft_address), abi=zk_nft_abi)

        async def approve_nft(gwei=None):
            # approve
            while True:
                if id_:
                    try:
                        nonce = await self.w3.eth.get_transaction_count(self.address)
                        await asyncio.sleep(2)
                        tx = await zkNft.functions.approve(
                            Web3.to_checksum_address(self.bridge_address), id_).build_transaction({
                            'from': self.address,
                            'gas': await zkNft.functions.approve(Web3.to_checksum_address(self.bridge_address),
                                                                 id_).estimate_gas(
                                {'from': self.address, 'nonce': nonce}),
                            'nonce': nonce,
                            'maxFeePerGas': int(await self.w3.eth.gas_price),
                            'maxPriorityFeePerGas': int((await self.w3.eth.gas_price) * 0.8)
                        })
                        if self.chain == 'bsc' or self.chain == 'core':
                            del tx['maxFeePerGas']
                            del tx['maxPriorityFeePerGas']
                            tx['gasPrice'] = await self.w3.eth.gas_price
                        logger.info(f'{self.address}:{self.chain} - начинаю апрув {self.nft} {id_}...')
                        sign = self.account.sign_transaction(tx)
                        hash = await self.w3.eth.send_raw_transaction(sign.rawTransaction)
                        status = await self.check_status_tx(hash)
                        if status == 1:
                            logger.success(
                                f'{self.address}:{self.chain} - успешно апрувнул {self.nft} {id_} : {scans[self.chain]}{self.w3.to_hex(hash)}...')
                            await self.sleep_indicator(random.randint(1, 10))
                            return True
                        else:
                            logger.info(f'{self.address}:{self.chain} - пробую апрув еще раз...')
                            await approve_nft()
                    except Exception as e:
                        error = str(e)
                        if 'nonce too low' in error or 'already known' in error:
                            logger.info(f'{self.address}:{self.chain} - ошибка при апруве, пробую еще раз...')
                            await approve_nft()
                        if 'INTERNAL_ERROR: insufficient funds' in error or 'insufficient funds for gas * price + value' in error:
                            logger.error(
                                f'{self.address}:{self.chain} - не хватает денег на газ, заканчиваю работу через 5 секунд...')
                            await asyncio.sleep(5)
                            return False
                        else:
                            logger.error(f'{self.address}:{self.chain} - {e}...')
                            await asyncio.sleep(2)
                            return False

        async def bridge_():
            bridge = self.w3.eth.contract(address=Web3.to_checksum_address(self.bridge_address),
                                          abi=bridge_lz_abi if self.nft == 'Pandra' and self.to not in ('combo', 'taiko') else bridge_abi)

            logger.info(f'{self.address}:{self.chain} - начинаю бридж {self.nft} {id_}...')
            while True:
                try:
                    if self.nft == 'Pandra' and self.to not in ('combo', 'taiko'):
                        nonce = await self.w3.eth.get_transaction_count(self.address)
                        await asyncio.sleep(2)
                        args = Web3.to_checksum_address(self.nft_address), id_, stargate_ids[
                            self.to], self.address, '0x000100000000000000000000000000000000000000000000000000000000001b7740' if self.to != 'mantle' \
                            else '0x00010000000000000000000000000000000000000000000000000000000000055730'
                        lzfee = (await bridge.functions.estimateFee(*args).call())
                        tx = await bridge.functions.transferNFT(*args).build_transaction({
                            'from': self.address,
                            'value': lzfee,
                            'nonce': nonce,
                            'maxFeePerGas': int(await self.w3.eth.gas_price),
                            'maxPriorityFeePerGas': int((await self.w3.eth.gas_price) * 0.8)
                        })
                        tx['gas'] = await self.w3.eth.estimate_gas(tx)
                    else:
                        to = chain_ids[self.to]
                        fee = await bridge.functions.fee(to).call()
                        enco = f'0x000000000000000000000000{self.address[2:]}'
                        nonce = await self.w3.eth.get_transaction_count(self.address)
                        tx = await bridge.functions.transferNFT(
                            Web3.to_checksum_address(self.nft_address), id_, to,
                            enco).build_transaction({
                            'from': self.address,
                            'value': fee,
                            'gas': await bridge.functions.transferNFT(
                                Web3.to_checksum_address(self.nft_address), id_, to,
                                enco).estimate_gas({'from': self.address, 'nonce': nonce, 'value': fee}),
                            'nonce': nonce,
                            'maxFeePerGas': int(await self.w3.eth.gas_price),
                            'maxPriorityFeePerGas': int((await self.w3.eth.gas_price) * 0.8)
                        })

                    if self.chain == 'bsc' or self.chain == 'core':
                        del tx['maxFeePerGas']
                        del tx['maxPriorityFeePerGas']
                        tx['gasPrice'] = await self.w3.eth.gas_price
                    sign = self.account.sign_transaction(tx)
                    hash = await self.w3.eth.send_raw_transaction(sign.rawTransaction)
                    status = await self.check_status_tx(hash)
                    if status == 1:
                        logger.success(
                            f'{self.address}:{self.chain} - успешно бриджанул {self.nft} {id_} в {self.to}: {scans[self.chain]}{self.w3.to_hex(hash)}...')
                        await self.sleep_indicator(random.randint(self.delay[0], self.delay[1]))
                        return self.privatekey, self.address, f'successfully bridged {self.nft} to {self.to}'
                    else:
                        logger.info(f'{self.address}:{self.chain} - пробую бриджить еще раз...')
                        await bridge_()
                except Exception as e:
                    error = str(e)
                    if 'insufficient funds' in error or 'gas required exceeds allowance' in error:
                        logger.error(
                            f'{self.address}:{self.chain} - не хватает денег на газ, заканчиваю работу через 5 секунд...')
                        await asyncio.sleep(5)
                        return self.privatekey, self.address, f'error bridge {self.nft} - not gas'
                    if 'nonce too low' in error or 'already known' in error:
                        logger.info(f'{self.address}:{self.chain} - ошибка при бридже, пробую еще раз...')
                        await bridge_()
                    else:
                        logger.error(f'{self.address}:{self.chain} - {e}')
                        return self.privatekey, self.address, f'error bridge {self.nft} - {e}'

        if await approve_nft(self):
            return await bridge_()
        else:
            return self.privatekey, self.address, f'error approve {self.nft}'


class ZkMessage(Help):
    def __init__(self, privatekey, chain, to, delay, proxy=None):
        self.privatekey = privatekey
        self.chain = chain
        self.to = random.choice(to) if type(to) == list else to
        self.w3 = Web3(Web3.AsyncHTTPProvider(rpcs[self.chain]),
                       modules={'eth': (AsyncEth,)}, middlewares=[])
        self.scan = scans[self.chain]
        self.account = self.w3.eth.account.from_key(self.privatekey)
        self.address = self.account.address
        self.delay = delay
        self.proxy = f'http://{proxy}' if proxy else None

    async def auth(self):
        ua = UserAgent()
        ua = ua.random
        headers = {
            'authority': 'api.zkbridge.com',
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'content-type': 'application/json',
            'origin': 'https://zkbridge.com',
            'referer': 'https://zkbridge.com/',
            'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': ua,
        }

        json_data = {
            'publicKey': self.address.lower(),
        }
        while True:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                            'https://api.zkbridge.com/api/signin/validation_message',
                            json=json_data, headers=headers, proxy=self.proxy) as response:
                        if response.status == 200:
                            msg = json.loads(await response.text())
                            msg = msg['message']
                            msg = encode_defunct(text=msg)
                            sign = self.w3.eth.account.sign_message(msg, private_key=self.privatekey)
                            signature = self.w3.to_hex(sign.signature)
                            json_data = {
                                'publicKey': self.address,
                                'signedMessage': signature,
                            }
                            return signature, ua
            except Exception as e:
                logger.error(f'{self.address}:{self.chain} - {e}')
                await asyncio.sleep(5)

    async def sign(self):
        # sign msg
        signature, ua = await self.auth()
        headers = {
            'authority': 'api.zkbridge.com',
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'content-type': 'application/json',
            'origin': 'https://zkbridge.com',
            'referer': 'https://zkbridge.com/',
            'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': ua,
        }
        json_data = {
            'publicKey': self.address.lower(),
            'signedMessage': signature,
        }
        while True:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post('https://api.zkbridge.com/api/signin',
                                            json=json_data, headers=headers, proxy=self.proxy) as response:
                        if response.status == 200:
                            token = (json.loads(await response.text()))['token']
                            headers['authorization'] = f'Bearer {token}'
                            return headers
                        await asyncio.sleep(5)

            except Exception as e:
                logger.error(F'{self.address}:{self.chain} - {e}')
                await asyncio.sleep(5)

    async def profile(self):
        headers = await self.sign()
        params = ''
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api.zkbridge.com/api/user/profile',
                                       params=params, headers=headers, proxy=self.proxy) as response:
                    if response.status == 200:
                        logger.success(f'{self.address}:{self.chain} - успешно авторизовался...')
                        return headers
        except Exception as e:
            logger.error(f'{self.address}:{self.chain} - {e}')
            return False

    async def check_status_lz(self):
        contract_msg = Web3.to_checksum_address(sender_msgs[self.chain])
        mailer = self.w3.eth.contract(address=contract_msg, abi=mailer_abi)
        try:
            if not await mailer.functions.layerZeroPaused().call():
                logger.success(f'{self.address}:{self.chain} - L0 активен...')
                return True
            else:
                logger.info(f'{self.address}:{self.chain} - L0 не активен, жду 30 секунд...')
                await asyncio.sleep(30)
        except Exception as e:
            await asyncio.sleep(1)

    async def msg(self, headers, contract_msg, msg, from_chain, to_chain, tx_hash):

        timestamp = time.time()

        json_data = {
            'message': msg,
            'mailSenderAddress': contract_msg,
            'receiverAddress': self.address,
            'receiverChainId': to_chain,
            'sendTimestamp': timestamp,
            'senderAddress': self.address,
            'senderChainId': from_chain,
            'senderTxHash': tx_hash,
            'sequence': random.randint(4500, 5000),
            'receiverDomainName': '',
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api.zkbridge.com/api/user/profile',
                                       json=json_data, headers=headers, proxy=self.proxy) as response:
                    if response.status == 200:
                        logger.success(f'{self.address}:{self.chain} - cообщение подтвержденно...')
                        return True
        except Exception as e:
            logger.error(f'{self.address}:{self.chain} - {e}')
            return False

    async def create_msg(self):
        n = random.randint(1, 10)
        string = []
        word_site = "https://www.mit.edu/~ecprice/wordlist.10000"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(word_site) as response:
                    if response.status == 200:
                        for i in range(n):
                            WORDS = [g for g in (await response.text()).split()]
                            string.append(random.choice(WORDS))

                        msg = ' '.join(string)
                        return msg
        except Exception as e:
            await asyncio.sleep(1)
            return await self.create_msg()

    async def send_msg(self):
        time_ = random.randint(start_delay[0], start_delay[1])
        logger.info(f'Начинаю работу через {time_} cекунд...')
        await asyncio.sleep(time_)
        data = await self.profile()
        if data:
            headers = data
        else:
            return self.privatekey, self.address, 'error - not auth'
        contract_msg = Web3.to_checksum_address(sender_msgs[self.chain])
        lz_id = stargate_ids[self.to]
        to_chain_id = chain_ids[self.to]
        from_chain_id = chain_ids[self.chain]
        message = await self.create_msg()
        dst_address = Web3.to_checksum_address(dst_addresses[self.to])
        lzdst_address = Web3.to_checksum_address(lzdst_addresses[self.to])
        mailer = self.w3.eth.contract(address=contract_msg, abi=mailer_abi)
        native_ = native[self.chain]

        while True:
            try:
                zkFee = await mailer.functions.fees(to_chain_id).call()
                lz_status = await self.check_status_lz()
                fee = await mailer.functions.estimateLzFee(lz_id, self.address, message).call()
                value = fee + zkFee
                logger.info(
                    f'{self.address}:{self.chain} - начинаю отправку сообщения в {self.to} через L0, предполагаемая комса - {(fee + zkFee) / 10 ** 18} {native_}...')
                nonce = await self.w3.eth.get_transaction_count(self.address)
                tx = await mailer.functions.sendMessage(to_chain_id, dst_address, lz_id, lzdst_address, fee,
                                                        self.address,
                                                        message).build_transaction({
                    'from': self.address,
                    'value': value,
                    'gas': await mailer.functions.sendMessage(to_chain_id, dst_address, lz_id, lzdst_address, fee,
                                                              self.address,
                                                              message).estimate_gas(
                        {'from': self.address, 'nonce': nonce,
                         'value': value}),
                    'nonce': nonce,
                    'maxFeePerGas': int(await self.w3.eth.gas_price),
                    'maxPriorityFeePerGas': int((await self.w3.eth.gas_price) * 0.8)
                })
                if self.chain == 'bsc' or self.chain == 'celo':
                    del tx['maxFeePerGas']
                    del tx['maxPriorityFeePerGas']
                    tx['gasPrice'] = await self.w3.eth.gas_price
                sign = self.account.sign_transaction(tx)
                hash_ = await self.w3.eth.send_raw_transaction(sign.rawTransaction)
                status = await self.check_status_tx(hash_)
                if status == 1:
                    logger.success(
                        f'{self.address}:{self.chain} - успешно отправил сообщение {message} в {self.to} : {self.scan}{self.w3.to_hex(hash_)}...')
                    await asyncio.sleep(5)
                    msg = await self.msg(headers, contract_msg, message, from_chain_id, to_chain_id,
                                         self.w3.to_hex(hash_))
                    if msg:
                        await self.sleep_indicator(random.randint(self.delay[0], self.delay[1]))
                        return self.privatekey, self.address, f'success sending message to {self.to}'
                else:
                    logger.info(f'{self.address}:{self.chain} - пробую еще раз отправлять сообщение...')
                    await self.send_msg()

            except Exception as e:
                error = str(e)
                if 'nonce too low' in error or 'already known' in error or 'Message already executed' in error:
                    await asyncio.sleep(5)
                    await self.send_msg()
                elif 'INTERNAL_ERROR: insufficient funds' in error or 'insufficient funds for gas * price + value' in error:
                    logger.error(
                        f'{self.address}:{self.chain} - не хватает денег на газ, заканчиваю работу через 5 секунд...')
                    await asyncio.sleep(5)
                    return self.privatekey, self.address, 'error - not gas'
                else:
                    logger.error(f'{self.address}:{self.chain} - {e}...')
                    return self.privatekey, self.address, 'error'


class Anniversary(Help):
    def __init__(self, privatekey, delay, api, proxy=None):
        self.privatekey = privatekey
        self.chain = 'bsc'
        self.w3 = Web3(Web3.AsyncHTTPProvider(rpcs[self.chain]),
                       modules={'eth': (AsyncEth,)}, middlewares=[])
        self.account = self.w3.eth.account.from_key(self.privatekey)
        self.address = self.account.address
        self.delay = delay
        self.proxy = f'http://{proxy}' if proxy else None
        self.moralisapi = api
        self.nft_address = Web3.to_checksum_address('0x8FC516dCdcC1f25F9c1352fDBdc8F3b4e164e596')
        self.nft = 'Medal Anniversary'
        self.bridge_address = Web3.to_checksum_address('0x4d4b02D4d4188A1d0Cf3D8290e9481321B94d864')

    async def auth(self):
        ua = UserAgent()
        ua = ua.random
        headers = {
            'authority': 'api.zkbridge.com',
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'content-type': 'application/json',
            'origin': 'https://zkbridge.com',
            'referer': 'https://zkbridge.com/',
            'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': ua,
        }

        json_data = {
            'publicKey': self.address.lower(),
        }
        while True:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post('https://api.zkbridge.com/api/signin/validation_message',
                                            json=json_data, headers=headers, proxy=self.proxy) as response:
                        if response.status == 200:
                            msg = json.loads(await response.text())
                            msg = msg['message']
                            msg = encode_defunct(text=msg)
                            sign = self.w3.eth.account.sign_message(msg, private_key=self.privatekey)
                            signature = self.w3.to_hex(sign.signature)
                            json_data = {
                                'publicKey': self.address,
                                'signedMessage': signature,
                            }
                            return signature, ua
            except Exception as e:
                logger.error(f'{self.address}:{self.chain} - {e}')
                await asyncio.sleep(5)

    async def sign(self):
        # sign msg
        signature, ua = await self.auth()
        headers = {
            'authority': 'api.zkbridge.com',
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'content-type': 'application/json',
            'origin': 'https://zkbridge.com',
            'referer': 'https://zkbridge.com/',
            'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': ua,
        }

        json_data = {
            'publicKey': self.address.lower(),
            'signedMessage': signature,
        }
        while True:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post('https://api.zkbridge.com/api/signin',
                                            json=json_data, headers=headers, proxy=self.proxy) as response:
                        if response.status == 200:
                            token = (json.loads(await response.text()))['token']
                            headers['authorization'] = f'Bearer {token}'
                            return headers

            except Exception as e:
                logger.error(F'{self.address}:{self.chain} - {e}')
                await asyncio.sleep(5)

    async def profile(self):
        headers = await self.sign()
        params = ''
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api.zkbridge.com/api/user/profile',
                                       params=params, headers=headers, proxy=self.proxy) as response:
                    if response.status == 200:
                        logger.success(f'{self.address}:{self.chain} - успешно авторизовался...')
                        return True
        except Exception as e:
            logger.error(f'{self.address}:{self.chain} - {e}')
            return False

    async def balance_and_get_id(self):
        try:
            api_key = self.moralisapi
            params = {
                "chain": self.chain,
                "format": "decimal",
                "token_addresses": [
                    self.nft_address
                ],
                "media_items": False,
                "address": self.address}

            result = evm_api.nft.get_wallet_nfts(api_key=api_key, params=params)
            id_ = int(result['result'][0]['token_id'])
            if id_:
                logger.success(f'{self.address}:{self.chain} - успешно найдена {self.nft} {id_}...')
                return id_
        except Exception as e:
            if 'list index out of range' in str(e):
                logger.error(f'{self.address}:{self.chain} - на кошельке отсутсвует {self.nft}...')
                return False
            else:
                logger.error(f'{self.address}:{self.chain} - {e}...')
                return False

    async def claim_first(self):
        try:
            nonce = await self.w3.eth.get_transaction_count(self.address)
            tx = {
                'from': self.address,
                'to': Web3.to_checksum_address(self.nft_address),
                'nonce': nonce,
                'value': 0,
                'data': '0x4e71d92d',
                'chainId': await self.w3.eth.chain_id,
                'gasPrice': await self.w3.eth.gas_price}
            tx['gas'] = int(await self.w3.eth.estimate_gas(tx))
            sign = self.account.sign_transaction(tx)
            hash = await self.w3.eth.send_raw_transaction(sign.rawTransaction)
            status = await self.check_status_tx(hash)
            if status == 1:
                logger.success(
                    f'{self.address}:{self.chain} - успешно заклеймил {self.nft} {scans[self.chain]}{self.w3.to_hex(hash)}...')
                await self.sleep_indicator(random.randint(self.delay[0], self.delay[1]))
                return True
            else:
                logger.info(f'{self.address}:{self.chain} - пробую клейм еще раз...')
                return await self.claim_first()
        except Exception as e:
            error = str(e)
            if 'insufficient funds' in error or 'gas required exceeds allowance' in error:
                logger.error(
                    f'{self.address}:{self.chain} - не хватает денег на газ, заканчиваю работу через 5 секунд...')
                await asyncio.sleep(5)
                return False
            if 'nonce too low' in error or 'already known' in error:
                logger.info(f'{self.address}:{self.chain} - ошибка при клейме, пробую еще раз...')
                return await self.claim_first()
            else:
                logger.error(f'{self.address}:{self.chain} - {e}')
                return False

    async def bridge_nft(self, to_chain):
        bridge = self.w3.eth.contract(address=self.bridge_address, abi=aniversary_abi)
        id_ = await self.balance_and_get_id()
        if not id_:
            return False

        lz_adapt = '0x00010000000000000000000000000000000000000000000000000000000000055730'

        async def get_fee():
            try:
                if to_chain == 'arbi':
                    args = Web3.to_checksum_address(self.nft_address), id_, chain_ids[to_chain], \
                        self.address, lz_adapt
                    fee = await bridge.functions.estimateFee(*args).call()
                else:
                    fee = await bridge.functions.fee(chain_ids[to_chain]).call()
                return fee
            except Exception as e:
                logger.error(e)
                await asyncio.sleep(1)
                return await get_fee()

        async def bridge_():
            fee = await get_fee()
            try:
                nonce = await self.w3.eth.get_transaction_count(self.address)
                args = self.nft_address, id_, chain_ids[to_chain], self.address, b'' if to_chain != 'arbi' else lz_adapt
                tx = await bridge.functions.transferNFT(*args).build_transaction({
                    'from': self.address,
                    'value': fee,
                    'nonce': nonce,
                    'gasPrice': await self.w3.eth.gas_price})
                sign = self.account.sign_transaction(tx)
                hash = await self.w3.eth.send_raw_transaction(sign.rawTransaction)
                status = await self.check_status_tx(hash)
                if status == 1:
                    logger.success(
                        f'{self.address}:{self.chain} - успешно забриджил {self.nft} в {to_chain} {scans[self.chain]}{self.w3.to_hex(hash)}...')
                    await self.sleep_indicator(random.randint(self.delay[0], self.delay[1]))
                    return True
                else:
                    logger.info(f'{self.address}:{self.chain} - пробую клейме еще раз...')
                    await self.claim_first()
            except Exception as e:
                error = str(e)
                if 'insufficient funds' in error or 'gas required exceeds allowance' in error:
                    logger.error(
                        f'{self.address}:{self.chain} - не хватает денег на газ, заканчиваю работу через 5 секунд...')
                    await asyncio.sleep(5)
                    return False
                if 'nonce too low' in error or 'already known' in error:
                    logger.info(f'{self.address}:{self.chain} - ошибка при бридже, пробую еще раз...')
                    return await bridge_()
                else:
                    logger.error(f'{self.address}:{self.chain} - {e}')
                    return False

        return await bridge_()

    async def do_anniversary_tasks(self):
        sign = await self.profile()
        if not sign:
            return self.privatekey, self.address, f'error while signing'

        id_ = await self.balance_and_get_id()
        if not id_:
            claim = await self.claim_first()
            if not claim:
                return self.privatekey, self.address, f'error while claiming'

        for chain in ['arbi', 'combo', 'opbnb', 'scroll']:
            bridge = await self.bridge_nft(chain)
            if not bridge:
                return self.privatekey, self.address, f'error while bridging to {chain}'

        return self.privatekey, self.address, f'success claim all 5 nfts'
