
with open("keys.txt", "r") as f:
    keys = [row.strip() for row in f]


# прокси - по желанию, но рекомендую при большом количестве кошельков,
# нужно вставить в формате log:pass@ip:port в файле proxyy.txt
with open("proxyy.txt", "r") as f:
    proxies = [row.strip() for row in f]

# rpc по желанию можно поменять(рекомендуется при большом количестве кошельков)
rpcs = {'bsc': 'https://bscrpc.com',
        'polygon': 'https://polygon-rpc.com',
        'core': 'https://rpc.coredao.org',
        'opbnb': 'https://opbnb-testnet-rpc.bnbchain.org',
        'celo': 'https://rpc.ankr.com/celo'}


# Количество кошельков для одновременного запуска, т.е если у вас 100 кошельков, и вы выбрали число 5,
# то скрипт поделит ваши кошельки на 20 частей по 5 кошельков которые будут запущены одновременно
wallets_in_batch = 5

# start_delay отвечает за начальную задержку между кошельками, нужна для одновременного запуска несколька кошелей, смотри wallets_in_batch выше
# рекомендую не менять для максимального рандома
start_delay = (1, 1000)

# перемешка кошельков
# вкл - 1, выкл - 0
shuffle_keys = 1

# перерыв между действиями
DELAY = (1, 200)

# moralis api key - https://admin.moralis.io/login идем сюда и получаем апи ключ, НУЖЕН DEFAULT KEY!, нужно для нахождения id нфт
MORALIS_API_KEY = ''

# cколько максимум секунд скрипт будет ждать подтверждения транзакции
max_wait_time = 150

# режимы работы, ниже представлена подробная информация, кто будет заебывать в чате буду банить
MODE = ''   # 'messenger' / 'nftbridger' / 'anniversary'

'''
    
    квест на оптравку сообщений, скрипт будет отправлять рандомный текст
    messenger  -  chain  только из bsc polygon и сelo
                  to  только в bsc, polygon, nova, ftm, mbeam
                  из CELO в FTM, BSC, POLYGON 
    
    
    квест на бридж и минт нфт
    nftbridger - для каждой нфт свои чейны, если ошибетесь - работать не будет
    
    данные ниже для работы в режиме nftbridger

    Pandra  -  chain - bsc, polygon, core, celo to - bsc, polygon, core, combo, celo, gnosis, metis, mantle
    
    anniversary  -  собирает все 5 нфт
    
'''

# cети  bsc  polygon  core  ftm  celo  nova  combo mantle taiko

# из какой сети минтить и бриджить / отправлять сообщение
chain = 'polygon'

# в какую сеть бриджить / отправлять сообщение
# либо 'определенная сеть' либо ['сеть', 'сеть'] для выбора рандомной сети (если это позволяет настройка выше), не читаешь гайд получаешь бан в чате
to = 'mantle'

# выбор нфт для минта и бриджа
# список нфт 'Pandra'
nft = 'Pandra'

