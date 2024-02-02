import asyncio
import csv

from utils import *
from config import *
from info import nfts_addresses

async def write_to_csv(key, address, result):
    with open('result.csv', 'a', newline='') as file:
        writer = csv.writer(file)

        if file.tell() == 0:
            writer.writerow(['key', 'address', 'result'])

        writer.writerow([key, address, result])


async def main():
    if len(keys) == 0:
        logger.error('Не вставлены приватные ключи в файл keys.txt!...')
        return
    for i in rpcs.values():
        if i == '':
            logger.error('Не вставлены rpc в файле config!...')
            return
    if not MODE:
        logger.error('Не выбран модуль!...')
        return
    if shuffle_keys:
        random.shuffle(keys)
    logger.info(f'Начинаю работу на {len(keys)} кошельках...')
    batches = [keys[i:i + wallets_in_batch] for i in range(0, len(keys), wallets_in_batch)]

    print(f'\n{" " * 32}автор - https://t.me/iliocka{" " * 32}\n')

    tasks = []
    for batch in batches:
        for key in batch:
            if proxies:
                proxy = random.choice(proxies)
            else:
                proxy = None
            if MODE == 'nftbridger':
                if MORALIS_API_KEY == '':
                    logger.error('Не вставлен апи ключ моралис!...')
                    return
                if nft not in nfts_addresses.keys():
                    logger.error('Неправильно вставлено название нфт!...')
                    return
                logger.info('Запущен режим минта и бриджа нфт...')
                zk = ZkBridge(key, DELAY, chain, to, MORALIS_API_KEY, proxy)
                tasks.append(zk.bridge_nft())

            if MODE == 'messenger':
                logger.info('Запущен режим отправки сообщений...')
                zk = ZkMessage(key, chain, to, DELAY, proxy)
                tasks.append(zk.send_msg())

            if MODE == 'anniversary':
                logger.info('Запущен режим клейма 5 нфт Anniversary...')
                zk = Anniversary(key, DELAY, MORALIS_API_KEY, proxy)
                tasks.append(zk.do_anniversary_tasks())

        res = await asyncio.gather(*tasks)

        for res_ in res:
            key, address_, info = res_
            await write_to_csv(key, address_, info)

        tasks = []

    logger.success(f'Успешно сделал {len(keys)} кошельков...')
    logger.success(f'muнетинг закончен...')
    print(f'\n{" " * 32}автор - https://t.me/iliocka{" " * 32}\n')
    print(f'\n{" " * 32}donate - EVM 0xFD6594D11b13C6b1756E328cc13aC26742dBa868{" " * 32}\n')
    print(f'\n{" " * 32}donate - trc20 TMmL915TX2CAPkh9SgF31U4Trr32NStRBp{" " * 32}\n')



if __name__ == '__main__':
    asyncio.run(main())
