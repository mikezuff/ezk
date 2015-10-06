%% -------------------------------------------------------------------
%%
%% ezk_packet_2_message: A module that contains functions to convert
%%                       incoming binary messages into Erlangdata.
%%
%% Copyright (c) 2011 Marco Grebe. All Rights Reserved.
%% Copyright (c) 2011 global infinipool GmbH.  All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------
-module(ezk_packet_2_message).
-export([get_message_typ/1, replymessage_2_reply/3, get_watch_data/1]).
-include_lib("../include/ezk.hrl").

-record(getdata, {czxid,
                  mzxid,
                  pzxid,
                  ctime,
                  mtime,
                  dataversion,
                  datalength,
                  number_children,
                  cversion,
                  aclversion,
                  ephe_owner}).

%% First stage of Message Passing.
%% The first part of the Message determines the type (heartbeat, watchevent, reply) and
%% the first part of the Header (which is necessary to find the right entry in
%% open_requests) if it is a reply.
%% Returns {heartbeat, HeartbeatBin} | {watchevent, Payload}
%%       | {normal, MessageId, Zxid, Payload}
get_message_typ(Data) ->
    case Data  of
%%% Heartbeat
        <<255,255,255,254, Heartbeat/binary>> ->
            {heartbeat, Heartbeat};
%%% Watchevents
    <<255,255,255,255, 255,255,255,255, 255,255,255,255 , 0,0,0,0, Payload/binary>> ->
        ?LOG(3, "packet_2_message: A Watchevent arrived"),
        {watchevent, Payload};
    <<255, 255, 255, 252, 0:64, Payload/binary>> ->
        {authreply, Payload};
%%% Normal Replys
        <<MessId:32, Zxid:64, Payload/binary>> ->
        ?LOG(3, "packet_2_message: A normal Message arrived"),
            {normal, MessId, Zxid, Payload}
    end.

%% A message typed as watchevent is processed
%% returns {child, Path, SyncConnected} | {data, Path, SyncConnected}
get_watch_data(Binary) ->
     <<TypInt:32, SyncConnected:32, PackedPath/binary>> = Binary,
     {Path, _Nothing} = unpack(PackedPath),
     case TypInt of
     1 ->
         Typ = node_created;
     2 ->
         Typ = node_deleted;
     3 ->
         Typ = data_changed;
     4 ->
         Typ = child_changed
     end,
     {Typ, binary_to_list(Path), SyncConnected}.

%% Gets a replybinary from the server and returns it as a parsed Erlang tupel.
%% First step is to filter if there was an error and pass it on to the server if there is.
%% If not the interpret_reply_data function is used to interpret the Payload.
replymessage_2_reply(CommId, Path, PayloadWithErrorCode) ->
    ?LOG(1,"packet_2_message: Trying to Interpret payload: ~w", [PayloadWithErrorCode]),
    Reply =
        case PayloadWithErrorCode of
        <<0,0,0,0,Payload/binary>> ->
            ?LOG(1
            ,"packet_2_message: Interpreting the payload ~w with commid ~w and Path ~s"
            ,[Payload, CommId, Path]),
            try interpret_reply_data(CommId, Path, Payload) of
                {Replydata, _} -> {ok, Replydata}
            catch
                throw:Error -> {error, Error}
            end;
        <<Err:32/signed-integer, _Payload/binary>> ->
            {error, err_2_atom(Err)}
        end,
    ?LOG(1, "The Reply is ~w",[Reply]),
    Reply.


err_2_atom(0)    -> ok;                 % successful op in failed multi transaction
err_2_atom(-101) -> no_dir;             % ZNONODE
err_2_atom(-102) -> no_rights;          % ZNOAUTH
err_2_atom(-103) -> bad_version;        % ZBADVERSION
err_2_atom(-108) -> childs_or_forbidden;% ZNOCHILDRENFOREPHEMERALS,  childs_are_forbidden??
err_2_atom(-110) -> dir_exists;         % ZNODEEXISTS
err_2_atom(-111) -> not_empty;          % ZNOTEMPTY
err_2_atom(-112) -> session_expired;    % ZSESSIONEXPIRED
err_2_atom(-113) -> invalid_callback;   % ZINVALIDCALLBACK
err_2_atom(-114) -> inval_acl;          % ZINVALIDACL
err_2_atom(-115) -> auth_failed;        % ZAUTHFAILED
err_2_atom(-116) -> closing;            % ZCLOSING
err_2_atom(-117) -> nothing;            % ZNOTHING
err_2_atom(-118) -> session_moved;      % ZSESSIONMOVED
err_2_atom(-119) -> not_read_only;      % ZNOTREADONLY
err_2_atom(-120) -> ephemeral_on_local_session; % ZEPHEMERALONLOCALSESSION
err_2_atom(-121) -> no_watcher;         % ZNOWATCHER
err_2_atom(-122) -> rw_server_found;    % ZRWSERVERFOUND
err_2_atom(Code) -> Code.

%% There is a pattern matching on the command id and depending on the command id
%% the Reply is interpreted.
%%% create --> Reply = The new Path
interpret_reply_data(1, _Path, Reply) ->
    <<LengthOfData:32, Data/binary>> = Reply,
    {ReplyPath, Left} = split_binary(Data, LengthOfData),
    {binary_to_list(ReplyPath), Left};
%%% delete --> Reply = Nothing --> use the Path
interpret_reply_data(2, Path, Reply) ->
    {Path, Reply};
%%% exists
interpret_reply_data(3, _Path, Reply) ->
    getbinary_2_list(Reply);
%%% get --> Reply = The data stored in the node and then all the nodes  parameters
interpret_reply_data(4, _Path, Reply) ->
    ?LOG(3,"P2M: Got a get reply"),
    <<LengthOfData:32/signed-integer, Data/binary>> = Reply,
    ?LOG(3,"P2M: Length of data is ~w",[LengthOfData]),
    {ReplyData, Left} = case LengthOfData of
                            -1 -> {<<"">>,Data};
                            _ -> split_binary(Data, LengthOfData)
                        end,
    ?LOG(3,"P2M: The Parameterdata is ~w",[Left]),
    ?LOG(3,"P2M: Data is ~w",[ReplyData]),
    {Parameter, Left2} = getbinary_2_list(Left),
    {{ReplyData, Parameter}, Left2};
%%% set --> Reply = the nodes parameters
interpret_reply_data(5, _Path, Reply) ->
    getbinary_2_list(Reply);

%%% get_acl --> A list of the Acls and the nodes parameters
interpret_reply_data(6, _Path, Reply) ->
    ?LOG(3,"P2M: Got a get acl reply"),
    <<NumberOfAcls:32, Data/binary>> = Reply,
    ?LOG(3,"P2M: There are ~w acls",[NumberOfAcls]),
    {Acls, Data2} = get_n_acls(NumberOfAcls, [],  Data),
    ?LOG(3,"P2M: Acls got parsed: ~w", [Acls]),
    {Parameter, Left} = getbinary_2_list(Data2),
    ?LOG(3,"P2M: Data got also parsed."),
    {{Acls, Parameter}, Left};
%%% set_acl --> Reply = the nodes parameters
interpret_reply_data(7, _Path, Reply) ->
    getbinary_2_list(Reply);
%%% ls --> Reply = a list of all children of the node.
interpret_reply_data(8, _Path, Reply) ->
    ?LOG(4,"packet_2_message: Interpreting a ls"),
    <<NumberOfAnswers:32, Data/binary>> = Reply,
    ?LOG(4,"packet_2_message: Number of Children: ~w",[NumberOfAnswers]),
    ?LOG(4,"packet_2_message: The Binary is: ~w",[Data]),
    {List, Left} =  get_n_paths(NumberOfAnswers, Data),
    ?LOG(4,"packet_2_message: Paths extracted."),
    ?LOG(4,"packet_2_message: Paths are: ~w",[List]),
    {lists:map(fun(A) -> list_to_binary(A) end, List), Left};

%%% sync --> Reply = the sync'd node path
interpret_reply_data(9, _Path, Reply) ->
    {[RPath], Left} = get_n_paths(1, Reply),
    ?LOG(4, "P2M: Got a sync reply for ~p", [RPath]),
    {RPath, Left};

%%% ls2 --> Reply = a list of the nodes children and the nodes parameters
interpret_reply_data(12, _Path, Reply) ->
    {<<NumberOfAnswers:32>>, Data} = split_binary(Reply, 4),
    {Children, Left} =  get_n_paths(NumberOfAnswers, Data),
    {Parameter, Left2} = getbinary_2_list(Left),
    {[{children, Children}, Parameter], Left2};

%%% multi --> Reply = list of multi_header and replies for each until done
interpret_reply_data(14, _Path, Reply) ->
    ?LOG(4, "P2M: Got a multi reply"),
    {MultiStatus, ReplyData, Left} = interpret_multi(ok, [], Reply),
    case MultiStatus of
        ok -> {lists:reverse(ReplyData), Left};
        error -> throw(lists:reverse(ReplyData))
    end.

%%----------------------------------------------------------------
%% Little Helpers (internally neede functions)
%%----------------------------------------------------------------

interpret_multi(_, ReplyData, <<-1:32/signed-integer, 0:8,
        _HErr:32/signed-integer, Err:32/signed-integer, MultiLoad/binary>>) ->
    ?LOG(4, "P2M: multi error ~p", [Err]),
    interpret_multi(error, [err_2_atom(Err) | ReplyData], MultiLoad);
interpret_multi(MultiStatus, ReplyData, <<Command:32/signed-integer, 0:8, _Err:32, MultiLoad/binary>>) ->
    {Reply, Left} = interpret_reply_data(Command, <<"multi">>, MultiLoad),
    interpret_multi(MultiStatus, [Reply | ReplyData], Left);
interpret_multi(MultiStatus, ReplyData, <<_Command:32, 1:8, _Err:32, Left/binary>>) ->
    ?LOG(4, "P2M: multi done"),
    {MultiStatus, ReplyData, Left}.

%% unpacks N paths from a Binary.
%% Returns {ListOfPaths , Leftover}
get_n_paths(0, Binary) ->
    {[],Binary};
get_n_paths(N, Binary) ->
    {ThisPathBin, ToProcessBin} = unpack(Binary),
    {RekResult, Left2} = get_n_paths(N-1, ToProcessBin),
    {[binary_to_list(ThisPathBin) | RekResult ], Left2}.

%% interprets the parameters of a node and returns a List of them.
getbinary_2_list(Binary) ->
    ?LOG(3,"p2m: Trying to match Parameterdata"),
    <<Czxid:64,                           Mzxid:64,
      Ctime:64,                           Mtime:64,
      DaVer:32,          CVer:32,         AclVer:32,    EpheOwner:64,
                         DaLe:32,         NumChi:32,    Pzxid:64, Left/binary>> = Binary,
    ?LOG(3,"p2m: Matching Parameterdata Successfull"),
    {#getdata{czxid          = Czxid,   mzxid     = Mzxid,
              ctime          = Ctime,   mtime     = Mtime,
              dataversion    = DaVer,   datalength= DaLe,
              number_children= NumChi,  pzxid     = Pzxid,
              cversion       = CVer,    aclversion= AclVer,
              ephe_owner     = EpheOwner}, Left}.

%% uses the first 4 Byte of a binary to determine the lengths of the data and then
%% returns a pair {Data, Leftover}
unpack(Binary) ->
    <<Length:32, Load/binary>> = Binary,
    split_binary(Load, Length).

%% Looks for the first N Acls in a Binary.
%% Returns {ListOfAclTripels, Leftover}
get_n_acls(0, Acls, Binary) ->
    ?LOG(3,"P2M: Last Acl parsed."),
    {Acls, Binary};
get_n_acls(N, Acls,  Binary) ->
    ?LOG(3,"P2M: Parse next acl from this: ~w.",[Binary]),
    <<0:27, A:1, D:1, C:1, W:1, R:1, Left/binary>>  = Binary,
    {Scheme, Left2}         = unpack(Left),
    ?LOG(3,"P2M: Scheme is: ~w.",[Scheme]),
    {Id,     NowLeft}       = unpack(Left2),
    ?LOG(3,"P2M: Id is: ~w.",[Id]),
    ?LOG(3,"P2M: The Permissiontupel is: ~w.",[{R,W,C,D,A}]),
    Permi = get_perm_from_tupel({R,W,C,D,A}),
    NewAcls = [{Permi, Scheme, Id} | Acls ],
    get_n_acls(N-1, NewAcls, NowLeft).

%% Interprets the Permissions of an Acl.
get_perm_from_tupel({1,W,C,D,A}) ->
    [r | get_perm_from_tupel({0,W,C,D,A})];
get_perm_from_tupel({0,1,C,D,A}) ->
    [w | get_perm_from_tupel({0,0,C,D,A})];
get_perm_from_tupel({0,0,1,D,A}) ->
    [c | get_perm_from_tupel({0,0,0,D,A})];
get_perm_from_tupel({0,0,0,1,A}) ->
    [d | get_perm_from_tupel({0,0,0,0,A})];
get_perm_from_tupel({0,0,0,0,1}) ->
    [a | get_perm_from_tupel({0,0,0,0,0})];
get_perm_from_tupel({0,0,0,0,0}) ->
    [].
