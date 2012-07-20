%% ===================================================================
%% Project: Erlang AES
%% File: aes.erl
%% Description: Advanced Encryption Standard
%% Author: CGSMCMLXXV <cgsmcmlxxv@gmail.com>
%% Copyright: 2012 CGSMCMLXXV (for Erlang implementation)
%% License: GNU GPL3 (if aomething else needed, drop an e-mail)
%% ===================================================================


-module(aes).

-define(S_BOX,[16#63,16#7c,16#77,16#7b,16#f2,16#6b,16#6f,16#c5,16#30,16#01,16#67,16#2b,16#fe,16#d7,16#ab,16#76,
               16#ca,16#82,16#c9,16#7d,16#fa,16#59,16#47,16#f0,16#ad,16#d4,16#a2,16#af,16#9c,16#a4,16#72,16#c0,
               16#b7,16#fd,16#93,16#26,16#36,16#3f,16#f7,16#cc,16#34,16#a5,16#e5,16#f1,16#71,16#d8,16#31,16#15,
               16#04,16#c7,16#23,16#c3,16#18,16#96,16#05,16#9a,16#07,16#12,16#80,16#e2,16#eb,16#27,16#b2,16#75,
               16#09,16#83,16#2c,16#1a,16#1b,16#6e,16#5a,16#a0,16#52,16#3b,16#d6,16#b3,16#29,16#e3,16#2f,16#84,
               16#53,16#d1,16#00,16#ed,16#20,16#fc,16#b1,16#5b,16#6a,16#cb,16#be,16#39,16#4a,16#4c,16#58,16#cf,
               16#d0,16#ef,16#aa,16#fb,16#43,16#4d,16#33,16#85,16#45,16#f9,16#02,16#7f,16#50,16#3c,16#9f,16#a8,
               16#51,16#a3,16#40,16#8f,16#92,16#9d,16#38,16#f5,16#bc,16#b6,16#da,16#21,16#10,16#ff,16#f3,16#d2,
               16#cd,16#0c,16#13,16#ec,16#5f,16#97,16#44,16#17,16#c4,16#a7,16#7e,16#3d,16#64,16#5d,16#19,16#73,
               16#60,16#81,16#4f,16#dc,16#22,16#2a,16#90,16#88,16#46,16#ee,16#b8,16#14,16#de,16#5e,16#0b,16#db,
               16#e0,16#32,16#3a,16#0a,16#49,16#06,16#24,16#5c,16#c2,16#d3,16#ac,16#62,16#91,16#95,16#e4,16#79,
               16#e7,16#c8,16#37,16#6d,16#8d,16#d5,16#4e,16#a9,16#6c,16#56,16#f4,16#ea,16#65,16#7a,16#ae,16#08,
               16#ba,16#78,16#25,16#2e,16#1c,16#a6,16#b4,16#c6,16#e8,16#dd,16#74,16#1f,16#4b,16#bd,16#8b,16#8a,
               16#70,16#3e,16#b5,16#66,16#48,16#03,16#f6,16#0e,16#61,16#35,16#57,16#b9,16#86,16#c1,16#1d,16#9e,
               16#e1,16#f8,16#98,16#11,16#69,16#d9,16#8e,16#94,16#9b,16#1e,16#87,16#e9,16#ce,16#55,16#28,16#df,
               16#8c,16#a1,16#89,16#0d,16#bf,16#e6,16#42,16#68,16#41,16#99,16#2d,16#0f,16#b0,16#54,16#bb,16#16]).

-define(R_CON,[[16#00, 16#00, 16#00, 16#00],
               [16#01, 16#00, 16#00, 16#00],
               [16#02, 16#00, 16#00, 16#00],
               [16#04, 16#00, 16#00, 16#00],
               [16#08, 16#00, 16#00, 16#00],
               [16#10, 16#00, 16#00, 16#00],
               [16#20, 16#00, 16#00, 16#00],
               [16#40, 16#00, 16#00, 16#00],
               [16#80, 16#00, 16#00, 16#00],
               [16#1b, 16#00, 16#00, 16#00],
               [16#36, 16#00, 16#00, 16#00]]).


-export([encrypt/3,decrypt/3]).

cipher(Input,W) ->
    Nb = 4,
    Nr = length(W) div Nb - 1,

    State0 = lists:map(fun(E) ->
                           lists:map(fun(X) ->
                                         lists:nth(X*Nb+E+1,Input)
                                     end,lists:seq(0,Nb-1))
                       end,lists:seq(0,3)),

    State1 = add_round_key(State0,W,0,Nb),

    State2 = lists:foldl(fun(E,Acc) ->
                           add_round_key(mix_columns(shift_rows(sub_bytes(case length(Acc)==0 of true -> State1; false -> Acc end,Nb),Nb)),W,E,Nb)
                       end,[],lists:seq(1,Nr-1)),

    State3 = add_round_key(shift_rows(sub_bytes(State2,Nb),Nb),W,Nr,Nb),

    lists:map(fun(E) ->
                  lists:nth(math:floor(E/4)+1,lists:nth((E rem 4)+1,State3))
              end,lists:seq(0,4*Nb-1)).

key_expansion(Key) ->
    Nb = 4,
    Nk = length(Key) div 4,
    Nr = Nk + 6,

    W0 = lists:map(fun(E) ->
                       [lists:nth(4*E+1,Key),lists:nth(4*E+2,Key),lists:nth(4*E+3,Key),lists:nth(4*E+4,Key)]
                   end,lists:seq(0,Nk-1)),

    W1 = lists:foldl(fun(E,Acc) ->
                       ACCL = length(Acc),
                       Temp0 = lists:map(fun(X) -> case ACCL==0 of true -> lists:nth(X,lists:nth(E,W0)); false -> lists:nth(X,lists:nth(ACCL,Acc)) end end,lists:seq(1,4)),
                       Temp1 = case (E rem Nk) == 0 of
                                   true ->
                                       T1 = sub_word(rot_word(Temp0)),
                                       lists:map(fun(X) ->
                                                     lists:nth(X+1,T1) bxor lists:nth(X+1,lists:nth((E div Nk)+1,?R_CON))
                                                 end,lists:seq(0,3));
                                   false -> case (Nk > 6) and ((E rem Nk) == 4) of true -> sub_word(Temp0); false -> Temp0 end
                               end,
                       Acc++[lists:map(fun(X) ->
                                           lists:nth(X,case (E-Nk+1) > Nk of true -> lists:nth(E-(2*Nk)+1,Acc); false -> lists:nth(E-Nk+1,W0) end) bxor lists:nth(X,Temp1)
                                       end,lists:seq(1,4))]
                   end,[],lists:seq(Nk,(Nb*(Nr+1))-1)),

    W0 ++ W1.

sub_bytes(S,Nb) ->
    lists:map(fun(E) ->
                  lists:map(fun(X) ->
                                lists:nth(lists:nth(X+1,lists:nth(E+1,S))+1,?S_BOX)
                            end,lists:seq(0,Nb-1))
              end,lists:seq(0,3)).

shift_rows(S,Nb) ->
    lists:map(fun(E) ->
                  lists:map(fun(X) ->
                                lists:nth(((X+E) rem Nb)+1,lists:nth(E+1,S))
                            end,lists:seq(0,3))
              end,lists:seq(0,3)).

mix_columns(S) ->
    T = lists:map(fun(E) ->
                      A = lists:map(fun(X) -> lists:nth(E+1,lists:nth(X,S)) end,lists:seq(1,4)),
                      B = lists:map(fun(X) -> B1 = lists:nth(E+1,lists:nth(X+1,S)), case (B1 band 16#80) == 0 of false -> B1 bsl 1 bxor 16#011b; true -> B1 bsl 1 end end,lists:seq(0,3)),
                      [lists:nth(1,B) bxor lists:nth(2,A) bxor lists:nth(2,B) bxor lists:nth(3,A) bxor lists:nth(4,A),
                       lists:nth(1,A) bxor lists:nth(2,B) bxor lists:nth(3,A) bxor lists:nth(3,B) bxor lists:nth(4,A),
                       lists:nth(1,A) bxor lists:nth(2,A) bxor lists:nth(3,B) bxor lists:nth(4,A) bxor lists:nth(4,B),
                       lists:nth(1,A) bxor lists:nth(1,B) bxor lists:nth(2,A) bxor lists:nth(3,A) bxor lists:nth(4,B)]
                  end,lists:seq(0,3)),
    lists:map(fun(E) ->
                  lists:map(fun(X) ->
                                lists:nth(E,lists:nth(X,T))
                            end,lists:seq(1,4))
              end,lists:seq(1,4)).

add_round_key(State,W,Rnd,Nb) ->
    lists:map(fun(E) ->
                  lists:map(fun(X) ->
                                lists:nth(X+1,lists:nth(E+1,State)) bxor lists:nth(E+1,lists:nth(Rnd*4+X+1,W))
                            end,lists:seq(0,Nb-1))
              end,lists:seq(0,3)).

sub_word(W) ->
    [lists:nth(lists:nth(1,W)+1,?S_BOX),lists:nth(lists:nth(2,W)+1,?S_BOX),lists:nth(lists:nth(3,W)+1,?S_BOX),lists:nth(lists:nth(4,W)+1,?S_BOX)].

rot_word(W) ->
    lists:sublist(W,2,length(W))++[lists:nth(1,W)].

encrypt(_PlainText,_Password,NBits) when ((NBits =/= 128) and (NBits =/= 192) and (NBits =/= 256)) -> [];

encrypt(PlainText,Password,NBits) when ((NBits =:= 128) or (NBits =:= 192) or (NBits =:= 256)) ->
    BlockSize = 16,
    PT = unicode:characters_to_list(PlainText,latin1),
    PTL = length(PT),
    PW = unicode:characters_to_list(Password,latin1),
    PWL = length(PW),

    NBytes = NBits div 8,

    PWBytes = lists:map(fun(E) ->
                            case E > PWL of
                                true -> 0;
                                false -> lists:nth(E,PW)
                            end
                        end,lists:seq(1,NBytes)),

    KeyT1 = cipher(PWBytes,key_expansion(PWBytes)),
    Key = KeyT1++lists:sublist(KeyT1,1,NBytes - 16),

    {Nonce1,Nonce2,Nonce3} = erlang:now(),
    NonceMs = Nonce3 div 1000,
    NonceSec = 1000000*Nonce1+Nonce2,
    NonceRnd = math:floor(random:uniform()*16#ffff),

    CounterBlock = [(NonceMs bsr 0) band 16#ff, (NonceMs bsr 8) band 16#ff,
                    (NonceRnd bsr 0) band 16#ff, (NonceRnd bsr 8) band 16#ff,
                    (NonceSec bsr 0) band 16#ff, (NonceSec bsr 8) band 16#ff,
                    (NonceSec bsr 16) band 16#ff, (NonceSec bsr 24) band 16#ff],

    KeySchedule = key_expansion(Key),

    BlockCount = math:ceil(PTL/BlockSize),

    CipherText = CounterBlock ++
                 lists:map(fun(E) ->
                               CB = CounterBlock ++
                                    [(E div 16#10000000) bsr 24, (E div 16#10000000) bsr 16, (E div 16#10000000) bsr 8, (E div 16#10000000) bsr 0,
                                     (E bsr 24) band 16#ff, (E bsr 16) band 16#ff, (E bsr 8) band 16#ff, (E bsr 0) band 16#ff],
                               CipherCntr = cipher(CB,KeySchedule),
                               BlockLength = case E < (BlockCount - 1) of true -> BlockSize; false -> ((PTL-1) rem BlockSize) + 1 end,
                               lists:map(fun(X) ->
                                             lists:nth(X+1,CipherCntr) bxor lists:nth(E*BlockSize+X+1,PT)
                                         end,lists:seq(0,BlockLength-1))
                           end,lists:seq(0,BlockCount-1)),

    base64:encode_to_string(lists:flatten(CipherText)).

decrypt(_CipherText,_Password,NBits) when ((NBits =/= 128) and (NBits =/= 192) and (NBits =/= 256)) -> [];

decrypt(CipherText,Password,NBits) when ((NBits =:= 128) or (NBits =:= 192) or (NBits =:= 256)) ->
    BlockSize = 16,
    CipherTxt = base64:decode_to_string(CipherText),
    PW = unicode:characters_to_list(Password,latin1),
    PWL = length(PW),

    NBytes = NBits div 8,

    PWBytes = lists:map(fun(E) -> case E > PWL of true -> 0; false -> lists:nth(E,PW) end end,lists:seq(1,NBytes)),
    Key1 = cipher(PWBytes,key_expansion(PWBytes)),
    Key = Key1 ++ lists:sublist(Key1,1,NBytes-16),

    CounterBlock = case length(CipherTxt) < 8 of true -> lists:sublist(CipherTxt,1,8)++lists:map(fun(_E) -> nan  end,lists:seq(1,8-length(CipherTxt))); false -> lists:sublist(CipherTxt,1,8) end,

    KeySchedule = key_expansion(Key),

    NBlocks = math:ceil((length(CipherTxt)-8)/BlockSize),

    CTG = lists:map(fun(E) ->
                        lists:sublist(CipherTxt,8+E*BlockSize+1,BlockSize)
                    end,lists:seq(0,NBlocks-1)),

    PT = lists:map(fun(E) ->
                       CB = lists:sublist(CounterBlock,1,8) ++
                            [((E div 16#100000000) bsr 24) band 16#ff,((E div 16#100000000) bsr 16) band 16#ff,((E div 16#100000000) bsr 8) band 16#ff,((E div 16#100000000) bsr 0) band 16#ff,
                             (E bsr 24) band 16#ff,(E bsr 16) band 16#ff,(E bsr 8) band 16#ff,(E bsr 0) band 16#ff],
                       CipherCntr = cipher(CB,KeySchedule),
                       lists:map(fun(X) ->
                                     lists:nth(X+1,CipherCntr) bxor lists:nth(X+1,lists:nth(E+1,CTG))
                                 end,lists:seq(0,length(lists:nth(E+1,CTG))-1))
                   end,lists:seq(0,NBlocks-1)),

    unicode:characters_to_list(lists:flatten(PT),latin1).
