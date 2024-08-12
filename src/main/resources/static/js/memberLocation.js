/**
 * 회원이 영남대학교 캠퍼스 내부에 존재하는지 판단하는 함수이다.
 */
function _isMemberInCampusArea(lat, lng) {
    let ccw1, ccw2, ccw3, ccw4, lat2 = lat + 2000000000, lng2 = lng, cnt = 0;
    let campusArea = [
        {latitude: 35.838775, longitude: 128.755746}, {latitude: 35.836260, longitude: 128.751529},
        {latitude: 35.835559, longitude: 128.752034}, {latitude: 35.833355, longitude: 128.752959},
        {latitude: 35.830822, longitude: 128.746873}, {latitude: 35.829841, longitude: 128.746121},
        {latitude: 35.827640, longitude: 128.746936}, {latitude: 35.826909, longitude: 128.748867},
        {latitude: 35.825211, longitude: 128.749129}, {latitude: 35.825336, longitude: 128.752263},
        {latitude: 35.823427, longitude: 128.753438}, {latitude: 35.821959, longitude: 128.756448},
        {latitude: 35.821963, longitude: 128.761118}, {latitude: 35.823154, longitude: 128.762848},
        {latitude: 35.826749, longitude: 128.764133}, {latitude: 35.829101, longitude: 128.764717},
        {latitude: 35.832711, longitude: 128.764963}, {latitude: 35.837232, longitude: 128.765727},
        {latitude: 35.837367, longitude: 128.762731}, {latitude: 35.837597, longitude: 128.758719}
    ];

    function ccw(x, xx, xxx, y, yy, yyy) {
        return (yyy - y) * (xx - x) - (yy - y) * (xxx - x);
    }

    function cmp(a, b, c) {
        return ((a < b ? a : b) <= c && c <= (a < b ? b : a));
    }

    for (let i = 0; i < campusArea.length; i++) {
        ccw1 = ccw(campusArea[i].latitude, campusArea[(i + 1) % campusArea.length].latitude, lat, campusArea[i].longitude, campusArea[(i + 1) % campusArea.length].longitude, lng);
        ccw2 = ccw(campusArea[i].latitude, campusArea[(i + 1) % campusArea.length].latitude, lat2, campusArea[i].longitude, campusArea[(i + 1) % campusArea.length].longitude, lng2);
        ccw3 = ccw(lat, lat2, campusArea[i].latitude, lng, lng2, campusArea[i].longitude);
        ccw4 = ccw(lat, lat2, campusArea[(i + 1) % campusArea.length].latitude, lng, lng2, campusArea[(i + 1) % campusArea.length].longitude);
        if ((ccw1 > 0 !== ccw2 > 0) && (ccw3 > 0 !== ccw4 > 0)) cnt++;
        if (ccw1 === 0.0 && cmp(campusArea[i].latitude, campusArea[(i + 1) % campusArea.length].latitude, lat) && cmp(campusArea[i].longitude, campusArea[(i + 1) % campusArea.length].longitude, lng)) {
            cnt = 1;
            break;
        }
    }

    return cnt % 2;
}

/**
 * navigator.geolocation.getCurrentPosition()에서 에러 발생 시 호출되는 함수이다.
 * 에러 코드에 맞는 메시지를 service2Home 페이지에 띄운다.
 */
function showErrorMsg(error) {
    let txt;
    switch (error.code) {
        case error.PERMISSION_DENIED:
            txt = "위치 정보 동의를 하지 않으면 서비스 2를 이용하실 수 없습니다."
            break;
        case error.POSITION_UNAVAILABLE:
            txt = "위치 정보를 사용할 수 없습니다."
            break;
        case error.TIMEOUT:
            txt = "위치 정보를 가져오는 데 실패했습니다."
            break;
        default:
            txt = "위치 정보를 가져오는 데 알 수 없는 오류가 발생했습니다."
            break;
    }
    bodyAlert(txt);
}

/**
 * 회원이 영남대학교 경산 캠퍼스 내에 위치하고 있는지 확인하고 경산 캠퍼스 내에 있다면 createRoom form을 서버에 전송하는 함수이다.
 */
function isMemberInCampusArea() {
    const form = document.getElementById("createRoom");
    if (navigator.geolocation) {
        // GeoLocation을 이용해서 접속 위치를 얻어옵니다
        navigator.geolocation.getCurrentPosition(function (position) {
            lat = position.coords.latitude; // 위도
            lng = position.coords.longitude; // 경도
            console.log(lat, lng);
            if (!_isMemberInCampusArea(lat, lng)) {
                let txt = "회원님은 현재 영남대학교 캠퍼스 외부에 있습니다. 따라서 서비스 2를 이용하실 수 없습니다.";
                bodyAlert(txt);
                return;
            }
            form.submit();
        }, showErrorMsg);
    } else {
        let txt = "현재 웹 브라우저가 위치 제공을 지원하지 않습니다. 따라서 서비스 2를 이용하실 수 없습니다."
        bodyAlert(txt);
    }
}