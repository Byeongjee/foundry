// Copyright 2018-2019 Kodebox, Inc.
// This file is part of CodeChain.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import { SDK } from "codechain-sdk";

export const faucetSecret =
    "ede1d4ccb4ec9a8bbbae9a13db3f4a7b56ea04189be86ac3a6a439d9a0a1addd";
export const faucetAccointId = SDK.util.getAccountIdFromPrivate(faucetSecret); // 6fe64ffa3a46c074226457c90ccb32dc06ccced1
export const faucetAddress = SDK.Core.classes.PlatformAddress.fromAccountId(
    faucetAccointId,
    { networkId: "tc" }
); // tccq9h7vnl68frvqapzv3tujrxtxtwqdnxw6yamrrgd

export const aliceSecret =
    "4aa026c5fecb70923a1ee2bb10bbfadb63d228f39c39fe1da2b1dee63364aff1";
export const alicePublic = SDK.util.getPublicFromPrivate(aliceSecret);
// 2a8a69439f2396c9a328289fdc3905d9736da9e14eb1a282cfd2c036cc21a17a5d05595160b7924e5ecf3f2628b440e601f3a531e92fa81571a70e6c695b2d08
export const aliceAccountId = SDK.util.getAccountIdFromPrivate(aliceSecret); // 40c1f3a9da4acca257b7de3e7276705edaff074a
export const aliceAddress = SDK.Core.classes.PlatformAddress.fromAccountId(
    aliceAccountId,
    { networkId: "tc" }
); // tccq9qvruafmf9vegjhkl0ruunkwp0d4lc8fgxknzh5

export const bobSecret =
    "91580d24073185b91904514c23663b1180090cbeefc24b3d2e2ab1ba229e2620";
export const bobPublic = SDK.util.getPublicFromPrivate(bobSecret);
// 545ebdc0b8fb2d0be77a27d843945950db6dbddc60477c0cf001751a797df8a41fc51fe5b76e371c8875ad1d0585a60af2eef2b5d631f7bfba86e7988c25088d
export const bobAccountId = SDK.util.getAccountIdFromPrivate(bobSecret); // e1361974625cbbcbbe178e77b510d44d59c9ca9d
export const bobAddress = SDK.Core.classes.PlatformAddress.fromAccountId(
    bobAccountId,
    { networkId: "tc" }
); // tccq8snvxt5vfwthja7z7880dgs63x4njw2n5e5zm4h

export const carolSecret =
    "40716f4fe0ad552d60dbfc8a0984482ac7191d1d9411c418fe1d15c93694ad47";
export const carolPublic = SDK.util.getPublicFromPrivate(carolSecret);
// aa9c8ece2f2716f92609a6b7148a0673a242351a0b3171115d9fb3e5a5f880dff8bc38706fcf4c905eb6642c4c2662340d196fed444e787678c8d07ea0f62684
export const carolAccountId = SDK.util.getAccountIdFromPrivate(carolSecret); // 72ead359812d6337d95ab2f43beeeead6429354a
export const carolAddress = SDK.Core.classes.PlatformAddress.fromAccountId(
    carolAccountId,
    { networkId: "tc" }
); // tccq9ew456esykkxd7et2e0gwlwa6kkg2f4fg4q3t2m

export const daveSecret =
    "922fcf44a30d5ae71c5be6aeb60e629e818d6030ba4c79168c20c594af5390d0";
export const davePublic = SDK.util.getPublicFromPrivate(daveSecret);
// aa9c8ece2f2716f92609a6b7148a0673a242351a0b3171115d9fb3e5a5f880dff8bc38706fcf4c905eb6642c4c2662340d196fed444e787678c8d07ea0f62684
export const daveAccountId = SDK.util.getAccountIdFromPrivate(davePublic); // c552b4b42b339c8a76eac21fa54369f85380b315
export const daveAddress = SDK.Core.classes.PlatformAddress.fromAccountId(
    daveAccountId,
    { networkId: "tc" }
); // tccq8z49d959veeeznkatpplf2rd8u98q9nz5zfqlpz

export const invalidSecret =
    "0000000000000000000000000000000000000000000000000000000000000000";
export const invalidAddress = "tccqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhhn9p3";

export const validator0Secret =
    "b05b7c1e9747330e97676a95f55d3e469794dfa2aaa3c958d2d3eb334da9fb55";
export const validator0Public = SDK.util.getPublicFromPrivate(validator0Secret);
// 4f1541fc6bdec60bf0ac6380a8e3914a469fe6cd4fa817c890d5823cfdda83932f61dc083e1b6736dadeceb5afd3fcfbac915e5fa2c9c20acf1c30b080114d7f
export const validator0AccountId = SDK.util.getAccountIdFromPrivate(
    validator0Secret
); // 6a8e5ec34cdb3cde78ebf4dfd8d84f00f437fddb
export const validator0Address = SDK.Core.classes.PlatformAddress.fromAccountId(
    validator0AccountId,
    { networkId: "tc" }
); // tccq94guhkrfndnehnca06dlkxcfuq0gdlamvw9ga4f
export const validator0BlsPublic =
    "0x8a362f3b7e98dd0288d4298fb620e7251ae3dc759584e3445bbfe01b1aac9626e245dc41a8656f951b2456379533779507463c0a2a2268d7c929914f3c26371f0ab0a2649ae648b2a830cdcb61187ec4ccc7b60ea8b5cef8fb1000ec690785bc";
// TODO: replace hard-coded values with SDK function call
// 0x prefix is required since the rlp library reads the prefix to encode the value
export const validator0PopSignature =
    "0xa14c2321cc2c4de037f371d80a2895d16afcea9cc0e98d2c122a46a990737695cb198e8314fb3a796590ef9335bfb8c8";
// TODO: replace hard-coded values with SDK function call
// 0x prefix is required since the rlp library reads the prefix to encode the valu

export const validator1Secret =
    "79d26d5788ca5f5ae87e8dd0f057124c2cfda11136aeb140f1d9ac3648d5b703";
export const validator1Public = SDK.util.getPublicFromPrivate(validator1Secret);
// 1ac8248deb29a58c4bdbfce031fb22c7ba3bcc9384bf6de058a1c8bef5a17422cf8ca26666a5505684db7364eabeed6fc678b02658ae7c1848a4ae6e50244cf2
export const validator1AccountId = SDK.util.getAccountIdFromPrivate(
    validator1Secret
); // c25b8e91fccd3b8b137b5faa7f86f656252ba2ee
export const validator1Address = SDK.Core.classes.PlatformAddress.fromAccountId(
    validator1AccountId,
    { networkId: "tc" }
); // tccq8p9hr53lnxnhzcn0d065lux7etz22azaca786tt
export const validator1BlsPublic =
    "0xa7865b12157bb34875726479acc5dc6c0e9a85bc2a1bd536bbdc082d2d2cb331373fb314f1cfe89bcfb9ef32b752064417ceb1bc8fc67dd73d1caa51cfe6ba1311661435ece91efb48f807887ad94588a40377265d4469d95f1229662e2fddf8";
// TODO: replace hard-coded values with SDK function call
// 0x prefix is required since the rlp library reads the prefix to encode the value
export const validator1PopSignature =
    "0x822a8cf830f03e075d40931107fc8d14af1d2eaa92cfe98888089a60e47fea246d6e5d361e3d473db7e04ea22d47ffbf";
// TODO: replace hard-coded values with SDK function call
// 0x prefix is required since the rlp library reads the prefix to encode the value

export const validator2Secret =
    "83352d249f5fe8d85b792dd26d70050b2f7fab02be9ea33e52c83a2be73a2700";
export const validator2Public = SDK.util.getPublicFromPrivate(validator2Secret);
// db3a858d2bafd2cb5382fcf366b847a86b58b42ce1fc29fec0cb0315af881a2ad495045adbdbc86ef7a777b541c4e62a0747f25ff6068a5ec3a052c690c4ff8a
export const validator2AccountId = SDK.util.getAccountIdFromPrivate(
    validator2Secret
); // d32d7cd32af1703400c9624ea3ba488d7a0e6d17
export const validator2Address = SDK.Core.classes.PlatformAddress.fromAccountId(
    validator2AccountId,
    { networkId: "tc" }
); // tccq8fj6lxn9tchqdqqe93yaga6fzxh5rndzu8k2gdw
export const validator2BlsPublic =
    "aa4b34bb0be98ff752def3fae13f9dc5ac3b494bd0295e684dd367842a5939cd8cfcea40c792497b0d2a009c96098a7e18d6318ddcb49f85658d3d53f0b032b29735701033395f5e03eeac65084feb50ebf21f5a1181ee1df6659632edb76331";
// TODO: replace hard-coded values with SDK function call
// 0x prefix is required since the rlp library reads the prefix to encode the value
export const validator2PopSignature =
    "b3540334534d13885921c6f3641e5865ba4e55626fdb8ee590ce87de10d1b58c9ef0a3884eb47e52de105bb825bebbd8";
// TODO: replace hard-coded values with SDK function call
// 0x prefix is required since the rlp library reads the prefix to encode the value

export const validator3Secret =
    "0afa81c02fba3671ec9578f3be040e0186b445e9dc37d8bf4a866c8636841836";
export const validator3Public = SDK.util.getPublicFromPrivate(validator3Secret);
// 42829b18de338aa3abf5e6d80cd511121bf9d34be9a135bbace32a3226479e7f3bb6af76c11dcc724a1666a22910d756b075d54d8fdd97be11efd7a0ac3bb222
export const validator3AccountId = SDK.util.getAccountIdFromPrivate(
    validator3Secret
); // 49acbedaea4afa1c00adea94856536fab532d927
export const validator3Address = SDK.Core.classes.PlatformAddress.fromAccountId(
    validator3AccountId,
    { networkId: "tc" }
); // tccq9y6e0k6af9058qq4h4ffpt9xmat2vkeyue23j8y
export const validator3BlsPublic =
    "893ec45952f9550384e7d0689766bdda923a7d7a22465f60ed3e33671e9e9ea7672c819267b5ab6bafa15948fb7e0e090d67df89de3fac918a4836ddb321c6e2dfda934ba2679c39eb8177e97989e4317de48e54a66e99cf77d6ec07728106c6";
// TODO: replace hard-coded values with SDK function call
// 0x prefix is required since the rlp library reads the prefix to encode the value
export const validator3PopSignature =
    "99f8d282646f106153e8ad7ceae97b3610127008e615d1e6ea266071dc7d04237192360f0cdcb222665cc7a076b78771";
// TODO: replace hard-coded values with SDK function call
// 0x prefix is required since the rlp library reads the prefix to encode the value

export const hitActionHandlerId = 1;
export const stakeActionHandlerId = 2;
