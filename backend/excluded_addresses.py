# Well-known infrastructure contracts that should never appear as "vulnerable bots".
# These end up in the dataset because they handle massive ETH flows,
# but they are not MEV bots.

EXCLUDED_ADDRESSES = {
    # ── Infrastructure contracts ──
    "0x00000000219ab540356cbb839cbe05303d7705fa",  # ETH2 Beacon Deposit Contract
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH
    "0x0000000000000000000000000000000000000000",  # Zero address

    # ── DEX Routers ──
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f",  # SushiSwap Router
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",  # Uniswap V2 Router
    "0xe592427a0aece92de3edee1f18e0157c05861564",  # Uniswap V3 Router
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",  # Uniswap V3 Router 02
    "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b",  # Uniswap Universal Router
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad",  # Uniswap Universal Router 2
    "0x1111111254fb6c44bac0bed2854e76f90643097d",  # 1inch v4 Router
    "0x1111111254eeb25477b68fb85ed929f73a960582",  # 1inch v5 Router
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff",  # 0x Exchange Proxy

    # ── Binance hot wallets ──
    "0x3f5ce5fbfe3e9af3971dd833d26ba9b5c936f0be",  # Binance 1
    "0xd551234ae421e3bcba99a0da6d736074f22192ff",  # Binance 2
    "0x564286362092d8e7936f0549571a803b203aaced",  # Binance 3
    "0x0681d8db095565fe8a346fa0277bffde9c0edbbf",  # Binance 4
    "0xfe9e8709d3215310075d67e3ed32a380ccf451c8",  # Binance 5
    "0x4e9ce36e442e55ecd9025b9a6e0d88485d628a67",  # Binance 6
    "0xbe0eb53f46cd790cd13851d5eff43d12404d33e8",  # Binance 7
    "0xf977814e90da44bfa03b6295a0616a897441acec",  # Binance 8
    "0x001866ae5b3de6caa5a51543fd9fb64f524f5478",  # Binance 9
    "0x85b931a32a0725be14285b66f1a22178c22d2571",  # Binance 10
    "0x708396f17127c42383e3b9014072679b2f60b82f",  # Binance 11
    "0xe0f0cfde7ee664943906f17f7f14342e76a5cec7",  # Binance 12
    "0x00bdb5699745f5b860228c8f939abf1b9ae374ed",  # Binance 13
    "0x28c6c06298d514db089934071355e5743bf21d60",  # Binance 14
    "0xdfd5293d8e347dfe59e90efd55b2956a1343963d",  # Binance 16
    "0x56eddb7aa87536c09ccc2793473599fd21a8b17f",  # Binance 17
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549",  # Binance 36

    # ── Other exchange wallets ──
    "0x2910543af39aba0cd09dbb2d50200b3e800a63d2",  # Kraken 13
    "0xae2d4617c862309a3d75a0ffb358c7a5009c673f",  # Kraken 10
    "0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0",  # Kraken 4
    "0xfa52274dd61e1643d2205169732f29114bc240b3",  # Kraken 7
    "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b",  # OKX 6
    "0x98ec059dc3adfbdd63429454aeb0c990fba4a128",  # OKX 4
    "0xab5c66752a9e8167967685f1450532fb96d5d24f",  # Huobi 1
    "0x6748f50f686bfbca6fe8ad62b22228b87f31ff2b",  # Huobi 2
    "0xfdb16996831753d5331ff813c29a93c76834a0ad",  # Huobi 3
    "0xeee27662c2b8eba3cd936a23f039f3189633e4c8",  # Huobi 34
    "0x5401dbab14052443d10f254287a516e153a8e471",  # Huobi 35
    "0x2b5634c42055806a59e9107ed44d43c426e58258",  # KuCoin 1
    "0xd6216fc19db775df9774a6e33526131da7d19a2c",  # KuCoin 2
    "0xeb2629a2734e272bcc07bda959863f316f4bd4cf",  # KuCoin 3
    "0x689c56aef474df92d44a1b70850f808488f9769c",  # KuCoin 4
    "0xa1d8d972560c2f8144af871db508f0b0b10a3fbf",  # KuCoin 5
    "0xf16e9b0d03470827a95cdfd0cb8a8a3b46969b91",  # KuCoin 6
    "0x738cf6903e6c4e699d1c2dd9ab8b67fcdb3121ea",  # KuCoin 7
    "0x88bd4d3e2997371bceefe8d9386c6b5b4de60346",  # KuCoin 8
    "0x1692e170361cefd1eb7240ec13d048fd9af6d667",  # KuCoin 9
    "0x2e3381202988d535e8185e7089f633f7c9998e83",  # KuCoin-funded trader
    "0x6262998ced04146fa42253a5c0af90ca02dfd2a3",  # Gate.io
    "0x0d0707963952f2fba59dd06f2b425ace40b492fe",  # Gate.io 2
    "0x1c4b70a3968436b9a0a9cf5205c787eb81bb558c",  # Gate.io 3
    "0xd793281b45cee87f7a5b5ca8f60c1ef87a7243c0",  # Gemini 3
    "0x07ee55aa48bb72dcc6e9d78256648910de513eca",  # Gemini 4
    "0x5f65f7b609678448494de4c87521cdf6cef1e932",  # Gemini 6
    "0x46340b20830761efd32832a74d7169b29feb9758",  # Crypto.com 2
    "0xcffad3200574698b78f32232aa9d63eabd290703",  # Crypto.com 1

    # ── Trading firms / Market makers ──
    "0x0f4ee9631f4be0a63756515141281a3e2b293bbe",  # Alameda Research 23
    "0x712d0f306956a6a4b4f9319ad9b9de48c5345996",  # Alameda Research 21
    "0x93793bd1f3e35a0efd098c30e486a860a0ef7551",  # Alameda Research 20
    "0x5d13f4bf21db713e17e04d711e0bf7eaf18540d6",  # Alameda Research 3
    "0x882a6a0e82b4e4d7f0e01c0cf3aa4bc0c1f1f5cc",  # Alameda Research
    "0x0000006daea1723962647b7e189d311d757fb793",  # Wintermute 1
    "0x4f3a120e72c76c22ae802d129f599bfdbc31cb81",  # Wintermute 2
    "0x00000000ae347930bd1e7b0f35588b92280f9e75",  # Wintermute 3
    "0xdbf5e9c5206d0db70a90108bf936da60221dc080",  # Wintermute (Exploited)
    "0xe74b28c2eae8679e3ccc3a94d5d0de83ccb84705",  # Jump Trading
    "0xcfc50541c3deaf725ce738ef87ace2ad778ba0c5",  # Jump Trading 2
    "0xf584f8728b874a6a5c7a8d4d387c9aae9172d621",  # Jump Trading 3
    "0x9507c04b10486547584c37bcbd931b2a4fee9a41",  # DWF Labs
    "0xa7efae728d2936e78bda97dc267687568dd593f3",  # OlympusDAO Treasury
    "0x6b75d8af000000e20b7a7ddf000ba900b4009a80",  # Flashbots Builder
}
