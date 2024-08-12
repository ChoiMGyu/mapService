const SENDED = 1, NOT_SENDED = 2, INVITED = "INVITED";
const NOT_INVITED = "NOT_INVITED", DUPLICATE_INVITE = "DUPLICATE_INVITE";
const SELF_INVITED = "SELF_INVITED";

let NotInCampusMessage = NOT_SENDED;

let serverRoomDeletionTime;

let $userlist = $("#userlist"); //jquery id가 "userlist"인 object 가져오기

let userList = [];

let roomStartTime = new Date();

/**
 * 지도의 중심이 변했는지 파악한다. 최단 경로를 인원마다 중심에 배치하는데 사용된다.
 */
kakao.maps.event.addListener(map, 'center_changed', function () {
    //console.log("Bound status: " + BoundStatus + ", map center changed: " + mapCenterChanged);
    if (BoundStatus === BOUND_CHANGED) {
        BoundStatus = BOUND_NOT_CHANGED;
        return;
    }
    mapCenterChanged = true;
    clearInterval(mapCenterChangedTimer);
    mapCenterChangedTimer = setInterval(() => mapCenterChanged = false, 4000);
    //alert('center changed!');
});

function getUserList(sender) {
    //현재 방에 있는 인원을 출력하는 함수(방장)
    //var $userlist = $("#userlist"); //jquery id가 "userlist"인 object 가져오기
    const url = new URL(location.href).searchParams;
    const roomId = url.get('roomId');
    //console.log("sender 출력 : " + sender);
    $.ajax({
        type: "GET",
        url: "/service2/room/curUserlist",
        data: {
            "roomId": roomId
        },
        success: function (data) {
            console.log(data);
            userList = [];
            var users = "";
            for (let i = 0; i < data.length; i++) {
                let userInfo = data[i];
                let userId = userInfo.userId;
                let nickname = userInfo.nickname;

                userList.push(nickname);

                //조건에 따라 강제 퇴장 버튼을 출력
                if (sender === userId) {
                    users += "<li class='dropdown-item'><span class='fw-bold'>방장 : </span>" + "<span class='test-start'>" + nickname + "</span></li>"
                } else {
                    users += "<li><hr class='dropdown-divider'></li>"
                    users += "<li class='dropdown-item'><span class='fw-bold'>일반회원 : </span> " + nickname + "<div></div><div class=\"d-grid gap-2\"><button class='btn btn-outline-primary btn-sm' data-role='exit' data-userid='" + userId + "'>퇴장</button></div>"
                        + "<div></div><div class=\"d-grid gap-2\"><button id='" + userId + "' class='btn btn-outline-primary btn-sm btn-assign'>임명</button></div>"
                        + "</li>"
                }
            }
            $userlist.html(users); //jquery html id="userlist"의 내용을 수정
        }
    })
}

function getUserListNormal(sender) {
    //현재 방에 있는 인원을 출력하는 함수(일반유저)
    //var $userlist = $("#userlist"); //jquery id가 "userlist"인 object 가져오기
    const url = new URL(location.href).searchParams;
    const roomId = url.get('roomId');
    //console.log("sender 출력 : " + sender);
    $.ajax({
        type: "GET",
        url: "/service2/room/curUserlist",
        data: {
            "roomId": roomId
        },
        success: function (data) {
            userList = [];
            let users = "";
            for (let i = 0; i < data.length; i++) {
                let userInfo = data[i];
                let userId = userInfo.userId;
                let nickname = userInfo.nickname;

                userList.push(nickname);

                if (sender === userId) {
                    users += "<li class='dropdown-item'><span class='fw-bold'>방장 : </span>" + "<span class='test-start'>" + nickname + "</span></li>"
                } else {
                    users += "<li class='dropdown-item'><span class='fw-bold'>일반회원 : </span>" + nickname + "</li>"
                }
                if (i !== data.length - 1) {
                    users += "<li><hr class='dropdown-divider'></li>"
                }
            }
            $userlist.html(users); //jquery html id="userlist"의 내용을 수정
        }
    })
}

function getInviteList() {
    //현재 방에 초대된 인원을 출력하는 함수
    var $invitelist = $("#invitelist"); //jquery id가 "invitelist"인 object 가져오기
    const url = new URL(location.href).searchParams;
    const roomId = url.get('roomId');
    //console.log("getUserList()가 호출됨, roomId는 다음과 같음 : " + roomId);
    $.ajax({
        type: "GET",
        url: "/service2/room/inviteUserlist",
        data: {
            "roomId": roomId
        },
        success: function (data) {
            var users = "";
            if (data.length === 0) {
                users += "<li><a class='dropdown-item'>초대한 유저가 없습니다</a></li>"
            }
            for (let i = 0; i < data.length; i++) {
                //console.log("data를 출력 data[i] : "+data[i]);
                users += "<li class='dropdown-item'>" + data[i] + "</li>"
                if (i !== data.length - 1) {
                    users += "<li><hr class='dropdown-divider'></li>"
                }
            }
            //console.log("users 출력 : " + users);
            $invitelist.html(users); //jquery html id="invitelist"의 내용을 수정
        }
    })
}

/**
 * 닉네임에 해당하는 회원을 초대하는데 사용되는 함수이다.
 */
function inviteMember() {
    resetError();
    $("#searchList").hide();
    let inviteNickname = document.getElementById("nickname");
    $.ajax({
        type: "GET",
        url: "/service2/room/invite",
        data: {
            roomId: roomId,
            nickname: inviteNickname.value
        },
        success: function (response) {
            console.log(response);
            if (response.inviteType === NOT_INVITED || response.inviteType === DUPLICATE_INVITE || response.inviteType === SELF_INVITED) {
                $("#nicknameError").text(response.message).show();
                $("#nickname").attr('class', "form-control fieldError");
                return;
            }
            addRecentInvite();
            bodyAlert(response.message);
            inviteNickname.value = '';
        },
        error: function (error) {
            console.log("에러발생 : " + error);
            $("#nicknameError").text(error.responseJSON[0].message).show();
            $("#nickname").attr('class', "form-control fieldError");
        }
    });
}

/**
 * userId에 해당하는 인원이 방장이 되면 방장이 사용할 수 있는 기능들을 보여주는 함수이다.
 */
function giveAuthority(userId, currentManager) {
    if (userId === currentManager) {
        $("#inviteMemberSection, #inviteUserlistSection, #deleteRoomBtn, #recentInviteSection").show();
        $("#deleteRoomSection").attr("class", "d-grid mt-3 mb-5");
    } else {
        //console.log(userId, currentManager);
        $("#inviteMemberSection, #inviteUserlistSection, #deleteRoomBtn, #recentInviteSection").hide();
        $("#deleteRoomSection").attr("class", "");
    }
}

/**
 * 방을 나가야 하는 경우 실행되는 함수이다.
 */
function leaveRoom(roomName, message) {
    let form = document.createElement("form");
    form.name = "expiredRoom";
    form.action = "/service2/room/leave";
    form.method = "get";
    form.style.display = 'none';

    let input1 = document.createElement("input");
    input1.value = roomName;
    input1.name = "roomName"
    form.appendChild(input1);

    let input2 = document.createElement("input");
    input2.value = message;
    input2.name = "reason";
    form.appendChild(input2);

    document.body.appendChild(form);
    form.submit();
}

/**
 * 방 사용 잔여 시간을 계산하는 함수이다.
 */
function getRoomRemainingTimeV2() {
    if (serverRoomDeletionTime !== undefined) {
        //console.log("현재 시간: "+(new Date()).toString()+"방 삭제 시간: "+serverRoomDeletionTime.toString());
        let remainingTime = serverRoomDeletionTime - new Date();
        //console.log(remainingTime);
        let h = Math.floor(remainingTime / 1000 / 60 / 60).toString().padStart(2, "0");
        remainingTime %= 1000 * 60 * 60;
        let m = Math.floor(remainingTime / 1000 / 60).toString().padStart(2, "0");
        remainingTime %= 1000 * 60;
        let s = Math.floor(remainingTime / 1000).toString().padStart(2, "0");
        let timeStr = h + "시간 " + m + "분 " + s + "초";
        $("#remainingTimeV2").text(timeStr);
    }
}

/**
 * 방 사용 삭제 시각을 표기하는 함수이다.
 */
function setRoomRemainingTimeV1(time) {
    let y = time.getFullYear().toString().padStart(4, "0");
    let month = (time.getMonth() + 1).toString().padStart(2, "0");
    let d = time.getDate().toString().padStart(2, "0");
    let h = time.getHours().toString().padStart(2, "0");
    let m = time.getMinutes().toString().padStart(2, "0");
    let s = time.getSeconds().toString().padStart(2, "0");
    $("#remainingTimeV1").text(y + "년 " + month + "월 " + d + "일 " + h + "시 " + m + "분 " + s + "초");
}

/**
 * roomRemainingTimeSection 클릭 시 방 만료 시간의 타입을 변경해 표기하는 역할을 한다.
 */
function changeRoomRemainingTimeType() {
    $("#roomRemainingTimeSection").click(function () {
        if ($("#remainingTimeV2").css("display") === "none") {
            $("#remainingTimeV1").hide();
            $("#remainingTimeV2").show();
            $("#roomRemainingTime").text("방 사용 잔여 시간");
        } else {
            $("#remainingTimeV2").hide();
            $("#remainingTimeV1").show();
            $("#roomRemainingTime").text("방 사용 만료 시각");
        }
    })
}

/**
 * 웹 페이지의 클릭 위치에 따라 nickname 입력 창 밑의 nickname search list의 표시 여부를 변경하는 함수이다.
 */
function changeSearchListDisplayType() {
    // inviteMemberSection이 아닌 다른 곳을 클릭하면 닉네임 자동 완성을 숨기는 기능을 한다.
    $(document).click(function () {
        let nickname = $("#nickname");
        if (!nickname.is(event.target) && !nickname.has(event.target).length && !$("#nickname").is(":focus")) {
            $("#searchList").hide();
        }
    });

    // nickname에 해당하는 인풋 태그가 포커스되면 닉네임 자동 완성을 표시하는 기능을 한다.
    $("#nickname").on("focus", function () {
        $("#searchList").show();
    })
}

/**
 * nickname에 해당하는 인풋 태그의 value가 달라지면 서버로부터 닉네임 자동 완성 리스트를 요청하고 닉네임 자동 완성 목록을 생성하는 함수이다.
 */
function searchNickname() {
    let previousNicknameInput = "";

    $("#nickname").on("input", function (e) {
        if (previousNicknameInput === $('#nickname').val()) return;
        previousNicknameInput = $('#nickname').val();
        //if(e.keyCode === 65 && e.ctrlKey) return;
        if ($("#nickname").val() === "") {
            $("#searchList").children().remove();
            return;
        }
        $("#nicknameError").hide();
        $("#nickname").attr('class', "form-control");
        $.ajax({
            type: "GET",
            url: "/searchNickname",
            data: {
                searchWord: $("#nickname").val()
            },
            success: function (response) {
                //console.log(response);
                let nicknameList = response.nicknameList;
                $("#searchList").children().remove();
                nicknameList.forEach(nickname => {
                    if (nicknameList.length !== 1 || nickname !== $("#nickname").val()) $("#searchList").append(
                        "<button type='button' class='list-group-item list-group-item-action' onclick='$(\"#nickname\").val(\"" + nickname + "\"); $(\"#searchList\").children().remove();'>" +
                        nickname +
                        "</button>"
                    )
                })
            },
            error: function (error) {
                console.log(error);
            }
        })
    });
}

function makeRecentInvite(lastInviteId) {
    return {
        lastInviteId
    };
}

function addRecentInvite() {
    let recentInvite;
    recentInvite = makeRecentInvite($("#nickname").val());
    let lastInvite = [];
    let previousInvite = JSON.parse(localStorage.getItem("recentInvite"));
    if (previousInvite != null) {
        for (let i = previousInvite.length === 10 ? 1 : 0; i < previousInvite.length; i++) {
            lastInvite.push(previousInvite[i]);
        }
        for (let i = 0; i < previousInvite.length; i++) {
            if (JSON.stringify(lastInvite[i]) === JSON.stringify(recentInvite)) {
                lastInvite.splice(i, 1);
            }
        }
    }

    lastInvite.push(recentInvite);
    localStorage.setItem("recentInvite", JSON.stringify(lastInvite));

    showRecentSearchList();
}

function showRecentSearchList() {
    //console.log("showRecentSearchList 호출");
    //localStorage.clear();
    let searchList = JSON.parse(localStorage.getItem("recentInvite"));

    let s = JSON.stringify(searchList);
    console.log(s);

    $("#recentInvite").empty();
    if (searchList == null || Object.keys(searchList).length === 0) {
        //console.log("조건문 만족");
        return;
    }
    var users = "";
    var $recentInvite = $("#recentInvite");
    for (let i = searchList.length - 1; i >= 0; i--) {
        if (searchList[i] !== null) {
            let text = searchList[i].lastInviteId.toString();
            //console.log("text는 다음과 같음 : " + text);
            users += "<li class='dropdown-item' onselectstart='return false' style='list-style: none; padding-bottom: 0; padding-top: 0; margin-bottom: 0.25rem'>"
                + "<span role = 'button' onclick='searchAgain(\"" + text + "\")'>"
                + text +
                "</span>" +
                "<button style='padding: 0.25rem; float:right' type='button' class='btn-close' onclick='deleteRecentInvite(" + i + ")'></button>" +
                "</li>";
            if (i !== 0) users += "<li><hr class='dropdown-divider'></li>"
        }
        $recentInvite.html(users); //jquery html id="invitelist"의 내용을 수정
    }
}

function searchAgain(lastinviteId) {
    $("#nickname").val(lastinviteId);
    inviteMember();
}

function deleteRecentInvite(idx) {
    console.log("idx : " + idx);
    let invite = [];
    let previousInvite = JSON.parse(localStorage.getItem("recentInvite"));
    for (let i = 0; i < previousInvite.length; i++)
        invite.push(previousInvite[i]);
    invite.splice(idx, 1);
    if (invite.length === 0) {
        $("#recentInvite").hide();
        localStorage.removeItem("recentInvite");
    } else {
        localStorage.setItem("recentInvite", JSON.stringify(invite));
    }
    //showRecentSearchList();
}

/**
 * 방에 혼자 있을 때 마커를 그리기 위해 사용되는 함수이다.
 */
function aloneInRoom(latitude, longitude, userId) {
    removeAllMarker();
    removeAllPolyline();
    removeAllCustomOverlay();
    addCustomOverlay(latitude, longitude, makeCustomOverlayContent(userId));
    if (mapCenterChanged === true) return;
    BoundStatus = BOUND_CHANGED;
    setBounds({latitude: latitude, longitude: longitude});
}


/**
 * 서비스 2에 사용되는 커스텀 오버레이의 컨텐츠를 만드는 함수이다.
 */
function makeCustomOverlayContent(text) {
    return "<div class='service2CustomOverlay rounded-pill border border-0 border-primary ps-2 pe-2 text-white bg-primary'><span>" + text + "</span></div>";
}

/**
 * 경로 업데이트 횟수를 변경하는 함수이다.
 */
function updateRouteUpdateCount(v) {
    let curTime = new Date();
    let t = curTime - roomStartTime;
    v.count++;
    v.recentCount++;
    v.countPer2Sec = (v.count / Math.floor(t / 2000)).toFixed(2);
    let countTxt = "경로 업데이트 횟수: " + v.count.toString();
    let countPer2SecAvgTxt = "2초당 경로 업데이트 횟수: " + v.countPer2Sec.toString();
    console.log("update: {time: " + t + ", count: " + v.count + ", countPer2Sec: " + v.countPer2Sec + "}");
    $("#routeUpdateCount").text(countTxt);
    $("#routeUpdateCountPer2Sec").text(countPer2SecAvgTxt);
    if (curTime - v.recentTime > 2000) {
        v.recentTime = curTime;
        let recentCountPer2SecTxt = "최근 2초간 경로 업데이트 횟수: " + v.recentCount.toString();
        $("#routeUpdateCountLast2Sec").text(recentCountPer2SecTxt);
        v.recentCount = 0;
    }
}

/**
 * 경로 업데이트 횟수 섹션의 display 여부를 바꾸는 함수이다.
 */
function displayRouteUpdateCount() {
    $("#displayRouteUpdateCountBtn").on("click", function () {
        if ($("#routeUpdateCountSection").css("display") === "none") {
            $("#displayRouteUpdateCountBtn").text("경로 업데이트 횟수 삭제");
            $("#routeUpdateCountSection").show();
        } else {
            $("#displayRouteUpdateCountBtn").text("경로 업데이트 횟수 표시");
            $("#routeUpdateCountSection").hide();
        }
    });
}

displayRouteUpdateCount();

$(document).ready(function () {

    giveAuthority(userId, owner);

    //console.log(roomName + ", " + roomId + ", " + userId);

    if (navigator.geolocation) {
        // GeoLocation을 이용해서 접속 위치를 얻어옵니다
        navigator.geolocation.getCurrentPosition(function (position) {
            let latitude = position.coords.latitude; // 위도
            let longitude = position.coords.longitude; // 경도

            if (NotInCampusMessage === NOT_SENDED && !_isMemberInCampusArea(latitude, longitude)) {
                NotInCampusMessage = SENDED;
                let txt = userId + "님은 현재 영남대학교 캠퍼스 외부에 있습니다. 따라서 경로가 올바르지 않을 수 있습니다.";
                bodyAlert(txt);
            }

            setInterval(getRoomRemainingTimeV2, 100); // getRoomRemainingTimeV2를 0.1초마다 실행해 방의 잔여 시간을 업데이트한다.

            let sockJs = new SockJS("/connection");
            //1. SockJS를 내부에 들고있는 stomp를 내어줌
            let stomp = Stomp.over(sockJs); //sockJs.onClose();
            let count = 0, countPer2Sec = 0, recentCount = 0, recentTime = roomStartTime;
            let v = {count: count, countPer2Sec: countPer2Sec, recentCount: recentCount, recentTime: recentTime};

            //2. connection이 맺어지면 실행
            stomp.connect({sender: userId, roomId: roomId}, function () { // { id:userId, roomId:roomId }는 connect 헤더에 포함되는 정보이다. SendInformationController 의 handleWebSocketConnectListener 함수에서 사용된다.
                //console.log("STOMP Connection");
                if (owner !== userId) {
                    $('#inviteUserlistSection').hide();
                }
                //3. subscribe(path, callback)으로 메세지를 받을 수 있음
                stomp.subscribe("/sub/service2/room/" + roomId, function (chat) {
                    let content = JSON.parse(chat.body);
                    //console.log("content 출력 : " + content);
                    let sender = content.sender;
                    let manager = content.manager;
                    let messageType = content.msgType;
                    let message = content.message;
                    let curMemberNum = content.curMemberNum;
                    let roomRemainingTime = content.roomRemainingTime;
                    let route = content.route;
                    let roomId = content.roomId;
                    let newOwner = content.owner;
                    //console.log("message: " + message);

                    //console.log("owner 출력 : " + owner);
                    //console.log("sender 출력 : " + sender);
                    if (owner === userId) {
                        //console.log("방장 userlist");
                        getUserList(owner); //userlist 업데이트(방장)
                    } else {
                        //console.log("일반유저 userlist")
                        getUserListNormal(owner); //userlist 업데이트(일반유저)
                    }
                    getInviteList(); //invitelist 업데이트
                    showRecentSearchList();

                    //console.log("방장 이름 출력 : " + owner);
                    //console.log("chatgpt 출력 : " + $("#" + sender).length);

                    if (manager != null) {
                        owner = manager;
                        giveAuthority(userId, manager);
                    }

                    switch (messageType) {
                        case "ENTER":
                            $("#curMemberNumber").text("현재 인원 수: " + curMemberNum + "명");
                            serverRoomDeletionTime = new Date(roomRemainingTime);
                            setRoomRemainingTimeV1(serverRoomDeletionTime);
                        case "NOT_IN_CAMPUS":
                            bodyAlert(message);
                            break;
                        case "CHANGE_OWNER":
                            // console.log("Change_Owner message 전송 완료");
                            // console.log("newOwner는 " + newOwner + "입니다.");
                            owner = newOwner;
                            giveAuthority(userId, newOwner);
                            bodyAlert(message);
                            //이전에는 subscribe message가 보내졌을 때 list 업데이트가 되었으므로
                            //방장이 바뀌더라도 message가 보내지는 타이밍과 다르면 업데이트가 느렸음
                            //방장을 바꾸자마자 리스트를 호출함으로써 업데이트 속도 향상
                            if (owner === userId) {
                                getUserList(owner); //userlist 업데이트(방장)
                            } else {
                                getUserListNormal(); //userlist 업데이트(일반유저)
                            }
                            getInviteList(); //invitelist 업데이트
                            break;
                        case "LEAVE":
                            if (sender === userId) {
                                leaveRoom(roomName, message);
                            }
                            bodyAlert(message);
                            $("#curMemberNumber").text("현재 인원 수: " + curMemberNum + "명");
                            serverRoomDeletionTime = new Date(roomRemainingTime);
                            setRoomRemainingTimeV1(serverRoomDeletionTime);
                            if (curMemberNum === 1) aloneInRoom(latitude, longitude, nickname);
                            break;
                        case "ROOM_EXPIRED": // 방의 시간이 만료된 경우 /service2/room/leave 으로 리다이렉트한다.
                            leaveRoom(roomName, message);
                            break;
                        case "ROUTE":
                            if (route[0] !== undefined) setMapRoute(SERVICE2, route, DEFAULT_OBJ_TYPE, DEFAULT_OBJ_TYPE, latitude, longitude);
                            else aloneInRoom(latitude, longitude, nickname);
                            updateRouteUpdateCount(v);
                    }
                });

                //4. send(path, header, message)로 메세지를 보낼 수 있음
                //stomp.send('/pub/room/enter', {}, JSON.stringify({roomId: roomId, sender: userId}));

                let delay = 2000;

                const options = {
                    enableHighAccuracy: true //높은 정확도의 위치 정보를 요구(베터리 사용량 증가)
                };
                if (navigator.geolocation) {
                    // watchPosition을 사용하여 위치 변경 감지
                    let watchId = navigator.geolocation.watchPosition(function (position) {
                        console.log("watchPosition 호출");

                        latitude = position.coords.latitude; // 위도
                        longitude = position.coords.longitude; // 경도

                        //console.log("watchPosition의 위도 경도 : " + latitude + ", " + longitude);
                        // 위치 변경 시 추가 처리 로직 -> setInterval을 사용해서 주기적으로 위치 전송을 하고 있기 때문에
                        // 주석처리 해도 되는 로직이나 사용자의 위치가 이동이 되었을 경우에도 위치를 서버에 보내주도록 한다
                        processPosition(latitude, longitude);

                    }, (e) => {
                        let txt = "위치 정보 제공 동의를 하지 않으면 서비스 2를 이용하실 수 없습니다.";
                        navigator.geolocation.clearWatch(watchId);
                        leaveRoom(roomName, txt);
                    }, options);

                    // setInterval을 사용하여 주기적으로 위치 정보 전송
                    setInterval(function () {
                        console.log("setInterval 호출");
                        navigator.geolocation.getCurrentPosition(function () {
                            latitude = position.coords.latitude; // 위도
                            longitude = position.coords.longitude; // 경도
                        }, (e) => {
                            let txt = "위치 정보 제공 동의를 하지 않으면 서비스 2를 이용하실 수 없습니다.";
                            navigator.geolocation.clearWatch(watchId);
                            leaveRoom(roomName, txt);
                        }, options);

                        //=============================================================================================//
                        // 테스트 위도, 경도이다. 경산 캠퍼스 내의 임의의 위치의 위도 경도를 얻을 수 있다.
                        /*latitude = 35.8310060 + Math.random() * 8 / 1000 - 4 / 1000; // 테스트 위도. 35.8310060 +- 0.004 의 위도 값을 가진다.
                        longitude = 128.7573493 + Math.random() * 8 / 1000 - 4 / 1000; // 테스트 경도 128.7573493 += 0.004 의 경도 값을 가진다.*/
                        //=============================================================================================//

                        //console.log("getCurrentPosition의 위도 경도 : " + latitude + ", " + longitude);
                        if (latitude !== undefined && longitude !== undefined) {
                            processPosition(latitude, longitude);
                        }
                    }, delay);

                } else {
                    let txt = "현재 웹 브라우저가 위치 제공을 지원하지 않아 서비스 2를 이용하실 수 없습니다.";
                    if (watchId !== -1) {
                        navigator.geolocation.clearWatch(watchId);
                        watchId = -1;
                    }
                    leaveRoom(roomName, txt);
                }

                // 위치를 처리하는 로직
                function processPosition(latitude, longitude) {
                    if (NotInCampusMessage === NOT_SENDED) {
                        if (!_isMemberInCampusArea(latitude, longitude)) {
                            NotInCampusMessage = SENDED;
                            let txt = `${userId}님은 현재 영남대학교 캠퍼스 외부에 있습니다. 따라서 경로가 올바르지 않을 수 있습니다.`;
                            stomp.send('/pub/room/out-campus', {}, JSON.stringify({
                                roomId: roomId,
                                sender: userId,
                                message: txt
                            }));
                        } else {
                            NotInCampusMessage = NOT_SENDED;
                        }
                    }
                    let msg = JSON.stringify({latitude: latitude, longitude: longitude});
                    stomp.send('/pub/room/route', {}, JSON.stringify({
                        roomId: roomId,
                        sender: userId,
                        message: msg
                    }));
                }


            });

            $('#userlist').on('click', '[data-role="exit"]', function () {
                //퇴장 버튼을 눌렀을 때 실행되는 함수
                var exitUserId = $(this).data('userid');
                console.log("exit userId: " + exitUserId);
                //alert(nickname + " 사용자의 퇴장 처리를 합니다.");
                stomp.send('/pub/room/leaveRoomUserId', {}, JSON.stringify({
                    roomId: roomId,
                    sender: exitUserId,
                    message: exitUserId + "이 방에서 강제 퇴장되었습니다."
                }));
            });

            $("#userlist").off("click", ".btn-assign").on("click", ".btn-assign", function (e) {
                newOwner = $(this).attr('id');
                //console.log(newOwner + " 임명 버튼이 클릭되었습니다");
                stomp.send('/pub/room/changeOwner', {}, JSON.stringify({
                    roomId: roomId,
                    sender: userId,
                    message: "방의 방장이 바뀌었어요!",
                    owner: newOwner
                }));
            });

            $("#button-send").on("click", function (e) {
                let msg = document.getElementById("msg");

                console.log(userId + ":" + msg.value);
                stomp.send('/pub/room/message', {}, JSON.stringify({
                    roomId: roomId,
                    sender: userId,
                    message: msg.value
                }));
                msg.value = '';
            });

            $("#leaveRoomBtn").on("click", function (e) {
                stomp.disconnect(function () {
                    location.href = "/";
                });
            });

            $("#deleteRoomBtn").on("click", function (e) {
                console.log("delete room");
                stomp.send('/pub/room/delete', {}, JSON.stringify({
                    roomId: roomId,
                    sender: userId,
                    message: null
                }));
            });

        }, (e) => {
            let txt = "위치 정보 제공 동의를 하지 않으면 서비스 2를 이용하실 수 없습니다.";
            leaveRoom(roomName, txt);
        });
    } else {
        let txt = "현재 웹 브라우저가 위치 제공을 지원하지 않습니다. 따라서 서비스 2를 이용하실 수 없습니다.";
        leaveRoom(roomName, txt);
    }

    changeSearchListDisplayType();
    changeRoomRemainingTimeType();
    searchNickname();
});