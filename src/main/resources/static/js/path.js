const SEARCH = "search";
const FIND_PATH = "findPath";
const BUILDING = "BUILDING";
const DEFAULT_OBJ_TYPE = "DEFAULT_OBJ_TYPE";
const ROUTE_IDX = -1;
const DEFAULT_LATITUDE = -1;
const DEFAULT_LONGITUDE = -181;
const BOUND_CHANGED = 1;
const BOUND_NOT_CHANGED = 0;
const SERVICE1 = 0;
const SERVICE2 = 1;
let mapCenterChanged;
let BoundStatus;
let mapCenterChangedTimer;

var container = document.getElementById('map');
var options = {
    center: new kakao.maps.LatLng(35.8330177, 128.7532086),
    level: 4 //지도 레벨 설정 (현재 100m)
};

var map = new kakao.maps.Map(container, options);

function selectTransportation(transportation) {
    if (transportation === '자동차') {
        $("#carBtn").attr('class', 'form-control btn btn-primary');
        $("#onFootBtn").attr('class', 'form-control btn btn-outline-primary');
        $("#transportation").val("자동차");
    } else if (transportation === '도보') {
        $("#onFootBtn").attr('class', 'form-control btn btn-primary');
        $("#carBtn").attr('class', 'form-control btn btn-outline-primary');
        $("#transportation").val("도보");
    }
}

function resetFindPathForm() {
    resetPathError();
    $("#carBtn").attr('class', 'form-control btn btn-outline-primary');
    $("#onFootBtn").attr('class', 'form-control btn btn-outline-primary');
    $("#transportation").val("");
    $("#startPoint").val("");
    $("#endPoint").val("");
    $("#start").val("");
    $("#end").val("");
}

function resetSearchForm() {
    $("#searchRequestForm").val("");
}

// 출발지와 도착지 사이의 폴리라인(카카오 api의 객체, 경로를 의미함)들을 저장한다. 새로운 경로 탐색 시 기존 경로를 삭제하기 위해 사용한다.
let drawRoute = [];
let markers = [];
let customOverlays = [];

/**
 * 사람의 위치에 마커를 추가하는 함수이다.
 */
function addMarker(latitude, longitude) {
    let marker = new kakao.maps.Marker({position: new kakao.maps.LatLng(latitude, longitude)});
    let alreadyExistingPosition = 0;
    for (let m of markers) {
        let mLatLng = m.getPosition();
        if (mLatLng.getLat() !== latitude || mLatLng.getLng() !== longitude) continue;
        alreadyExistingPosition = 1;
        break;
    }
    if (alreadyExistingPosition) return;
    //console.log("Add marker, latitude: " + latitude + ", longitude: " + longitude);
    drawMarker(marker);
    markers.push(marker);
}

/**
 * 페이징 할 때 마커를 찍는 함수이다
 */
function addMarkerPage(latitude, longitude) {
    let marker;

    var imageSrc = '/img/location-pin.png', // 마커이미지의 주소입니다
        imageSize = new kakao.maps.Size(64, 69), // 마커이미지의 크기입니다
        imageOption = {offset: new kakao.maps.Point(27, 69)}; // 마커이미지의 옵션입니다. 마커의 좌표와 일치시킬 이미지 안에서의 좌표를 설정합니다.

    var markerImage = new kakao.maps.MarkerImage(imageSrc, imageSize, imageOption),
        markerPosition = new kakao.maps.LatLng(latitude, longitude); // 마커가 표시될 위치입니다

    marker = new kakao.maps.Marker({
        position: markerPosition,
        image: markerImage // 마커이미지 설정
    });
    drawMarker(marker);
    markers.push(marker);
}

/**
 * 마커를 지도에 그리는 함수이다.
 */
function drawMarker(marker) {
    marker.setMap(map);
}

/**
 * 사람의 위치에 커스텀 오버레이를 추가하는 함수이다.
 */
function addCustomOverlay(latitude, longitude, content) {
    let customOverlay = new kakao.maps.CustomOverlay({
        position: new kakao.maps.LatLng(latitude, longitude),
        content: content,
        yAnchor: 1
    })
    let alreadyExistingPosition = 0;
    for (let c of customOverlays) {
        let cLatLng = c.getPosition()
        if (cLatLng.getLat() !== latitude || cLatLng.getLng() !== longitude) continue;
        alreadyExistingPosition = 1;
        break;
    }
    if (alreadyExistingPosition) return;
    drawCustomOverlay(customOverlay);
    customOverlays.push(customOverlay);
}

/**
 * 커스텀 오버레이를 지도에 그리는 함수이다.
 */
function drawCustomOverlay(customOverlay) {
    customOverlay.setMap(map);
}

// 지도 위에 표시되고 있는 마커를 모두 제거합니다
function removeAllMarker() {
    //console.log("removeMarker() 호출됨");
    for (var i = 0; i < markers.length; i++) {
        markers[i].setMap(null);
    }
    markers = [];
}

// 지도 위에 표시되고 있는 폴리라인을 모두 제거합니다
function removeAllPolyline() {
    //console.log("removePolyline() 호출됨");
    for (var i = 0; i < drawRoute.length; i++) {
        drawRoute[i].setMap(null);
    }
    drawRoute = [];
}

/**
 * 지도 위에 표시되고 있는 커스텀 오버레이를 모두 제거합니다
 */
function removeAllCustomOverlay() {
    for (let c of customOverlays) {
        c.setMap(null);
    }
    customOverlays = [];
}

// JavaScript 코드
// findPlace 함수 정의
/*function findPlace() {
    // 입력된 값을 가져와서 query 변수에 저장
    console.log("findPlace() 함수 호출됨");
    $("#searchPlaceSection").attr('class', 'mt-3 mb-5');
    resetPlaceError();
    if (!isPlaceEmpty()) return;
    var searchContent = $("#searchRequestForm").val();
    console.log("검색 내용:", searchContent);
    resetPathError();
    // Ajax 요청 보내기
    $.ajax({
        type: "GET",
        url: "/searchPlace",
        data: {
            searchContent: searchContent
        },
        success: function (response) {
            // 서버로부터의 응답을 처리
            console.log("SearchController에서 반환하는 response:", response);

            if (!response.name) {
                resetPlaceError();
                $("#searchRequestForm").attr('class', "form-control fieldError").focus();
                $("#searchPlaceError").text('검색 내용이 존재하지 않습니다').show();
                return;
            }

            var latitude = response.latitude;
            var longitude = response.longitude;
            console.log("검색된 장소의 위도:", latitude);
            console.log("검색된 장소의 경도:", longitude);

            //현재 지도에 있는 마커들을 지움
            removeAllMarker();
            //resetFindPathForm();
            $("#findPathSection").attr('class', 'mb-5');
            $("#pathInfoSection").hide();
            removeAllPolyline();

            //마커를 생성하면서 마커를 배열에 넣음
            /!*setBounds(response);
            addMarker(response.latitude, response.longitude);*!/

            /!*====================================================================================================*!/
            /!*최근 검색 추가*!/
            addRecentSearch(SEARCH);
            /!*====================================================================================================*!/


            /!*====================================================================================================*!/
            /!*검색 정보 제공*!/
            $("#findPathSection").hide();
            $("#pathInfoSection").hide();
            $("#recentSearchSection").hide();
            /!*$("#searchInfoSection").show();
            $("#searchName").text(response.name);
            if (response.objectType === BUILDING) $("#searchAddress").text(response.address).show();
            else $("#searchAddress").hide();
            $("#searchDescription").text(response.description);*!/

            $("#pageInfoSection").show();
            $("#homeButton").show();
            //console.log("searchContent는 다음과 같음 : " + searchContent);
            loadPage(0);
            /!*====================================================================================================*!/
        },
        error: function (xhr, status, error) {
            // 에러 처리
            console.error("에러 발생:", error);
            //var searchContent = document.getElementById("searchRequestForm").value;

            let isEnd = false;
            error.responseJSON.find(function (err) {
                if (err.field !== "searchContent") return;
                isEnd = true;
                $("#searchPlaceError").text(err.message).show();
                $("#searchRequestForm").attr('class', "form-control fieldError").focus();
            });
        }
    });
}*/

/**
 * 검색 결과의 설명 부분을 클릭하면 클릭된 건물이나 랜드마크의 마커를 커스텀 마커로 변경하는 함수이다.
 */
function changeToCustomMarker(latitude, longitude) {
    //removeAllMarker();
    markers.forEach(function (marker) {
        let latLng = marker.getPosition();
        //console.log("getLat: " + latLng.getLat().toFixed(10) + ", latitude: " + latitude.toFixed(10));
        //console.log("getLng: " + latLng.getLng().toFixed(10) + ", longitude: " + longitude.toFixed(10));
        marker.setImage(null);
        if (latLng.getLat().toFixed(10) === latitude.toFixed(10) && latLng.getLng().toFixed(10) === longitude.toFixed(10)) {
            var imageSrc = '/img/location-pin.png', // 마커이미지의 주소입니다
                imageSize = new kakao.maps.Size(64, 69), // 마커이미지의 크기입니다
                imageOption = {offset: new kakao.maps.Point(27, 69)}; // 마커이미지의 옵션입니다. 마커의 좌표와 일치시킬 이미지 안에서의 좌표를 설정합니다.

            var markerImage = new kakao.maps.MarkerImage(imageSrc, imageSize, imageOption);
            marker.setImage(markerImage);
        }
    });
}

/**
 * searchWord를 검색했을 때 pageNumber의 페이지를 불러오는 함수이다.
 * 페이징 할 때 사용하는 함수이다.
 */
function loadPage(pageNumber) {
    // 입력된 값을 가져와서 query 변수에 저장
    console.log("loadPage() 함수 호출됨");
    $("#searchPlaceSection").attr('class', 'mt-3 mb-5');
    resetPlaceError();
    if (!isPlaceEmpty()) return;
    var searchContent = $("#searchRequestForm").val();
    console.log("검색 내용:", searchContent);
    resetPathError();
    var pageSize = 3; // 한 페이지에 보이는 데이터 개수
    var pageGroupSize = 5; // 페이지 그룹 단위
    var firstResult = true;

    //console.log("loadPage가 searchWord : " + searchWord + "로 호출되었음");
    $.get('/searchObjectsPage', {searchWord: searchContent, page: pageNumber, size: pageSize}, function (pageList) {
        //console.log("페이징 컨트롤러 호출됨");
        if (pageList.content.length > 0) {
            removeAllMarker();
            removeAllPolyline();
            /*====================================================================================================*/
            /*최근 검색 추가*/
            addRecentSearch(SEARCH);
            /*====================================================================================================*/


            /*====================================================================================================*/
            /*검색 정보 제공*/
            $("#findPathSection").hide();
            $("#pathInfoSection").hide();
            $("#recentSearchSection").hide();
            $("#pageInfoSection").show();
            $("#homeButton").show();
            /*====================================================================================================*/

            var firstItem = true;
            var contentHtml = '<ul id="searchInfo" class="list-unstyled">';
            pageList.content.forEach(function (item) {
                contentHtml += '<hr>';
                contentHtml += '<li onclick="changeToCustomMarker(' + item.latitude + ', ' + item.longitude + ');">';
                contentHtml += '    <h6><b>' + item.name + '</b></h6>';
                if (item.objectType === BUILDING) contentHtml += '  <address>' + item.address + '</address>';
                contentHtml += '    <p>' + item.description + '</p>';
                contentHtml += '    <div class="d-flex justify-content-center">';
                contentHtml += '        <button class="btn btn-outline-primary me-1" type="button" onclick="setSearchStartPoint(\'' + item.name + '\')">출발</button>';
                contentHtml += '        <button class="btn btn-primary" type="button" onclick="setSearchEndPoint(\'' + item.name + '\')">도착</button>';
                contentHtml += '    </div>';
                contentHtml += '</li>';
                // console.log("item의 name: " + item.name);
                // console.log("item의 latitude: " + item.latitude);
                // console.log("item의 longitude: " + item.longitude);
                //addMarker(item.latitude, item.longitude);
                if(firstItem) {
                    addMarkerPage(item.latitude, item.longitude);
                    firstItem = false;
                }
                else {
                    addMarker(item.latitude, item.longitude);
                }
                if (firstResult) firstResult = false;
            });
            contentHtml += '<hr>';


            setBoundsPage();
            var paginationHtml = contentHtml + '<ul class="pagination justify-content-center">';
            var totalPages = pageList.totalPages; //전체 페이지 수
            var startPageGroup = Math.floor(pageNumber / pageGroupSize) * pageGroupSize + 1;
            //현재 페이지 그룹의 시작 페이지 번호

            var endPageGroup = Math.min(startPageGroup + pageGroupSize - 1, totalPages);
            //현재 페이지 그룹의 끝 페이지 번호, 단 마지막 페이지를 초과하는 경우 totalPages로 설정

            // console.log("pageNumber : " + pageNumber);
            // console.log("pageSize : " + pageSize);
            // console.log("totalPages : " + totalPages);
            // console.log("startPageGroup : " + startPageGroup);
            // console.log("endPageGroup : " + endPageGroup);

            if (pageNumber > 0) {
                paginationHtml += '<li class="page-item"><a class="page-link" href="#" data-page="' + (pageNumber - 1) + '">&lt;</a></li>';
            } else {
                paginationHtml += '<li class="page-item disabled"><a class="page-link" href="#" tabindex="-1" aria-disabled="true">&lt;</a></li>';
            }

            for (var page = startPageGroup; page <= endPageGroup; page++) {
                paginationHtml += '<li class="page-item ' + (page === pageNumber + 1 ? 'active' : '') + '"><a class="page-link" href="#" data-page="' + (page - 1) + '">' + page + '</a></li>';
            }

            if (pageNumber < totalPages - 1) {
                paginationHtml += '<li class="page-item"><a class="page-link" href="#" data-page="' + (pageNumber + 1) + '">&gt;</a></li>';
            } else {
                paginationHtml += '<li class="page-item disabled"><a class="page-link" href="#" tabindex="-1" aria-disabled="true">&gt;</a></li>';
            }

            paginationHtml += '</ul>';
            $('#pagination-container').html(paginationHtml);

            // 페이지 링크 클릭 이벤트 핸들러
            $('.page-link').on('click', function (e) {
                e.preventDefault();
                var selectedPage = $(this).data('page');
                loadPage(selectedPage);
                removeAllMarker();
            });
        } else {
            $('#pagination-container').html('<p>No results found</p>');
            resetPlaceError();
            $("#searchRequestForm").attr('class', "form-control fieldError").focus();
            $("#searchPlaceError").text('검색 내용이 존재하지 않습니다').show();
        }
    }).fail(function (xhr, status, error) {
        // 에러 처리
        console.error("에러 발생:", error);
        //var searchContent = document.getElementById("searchRequestForm").value;

        let isEnd = false;
        error.responseJSON.find(function (err) {
            if (err.field !== "searchContent") return;
            isEnd = true;
            $("#searchPlaceError").text(err.message).show();
            $("#searchRequestForm").attr('class', "form-control fieldError").focus();
        });
    });
}

/**
 * 페이지에 나온 결과의 마커들을 한 화면에서 보게 해주는 함수이다.
 */
function setBoundsPage() {
    console.log("페이징에 의한 setBounds");

    var bounds = new kakao.maps.LatLngBounds();

    markers.forEach(function (marker) {
        bounds.extend(marker.getPosition());
    });
    map.setBounds(bounds);
}


// 최근 검색 객체를 생성하는 함수이다.
function makeRecentSearch(search, transportation, start, end) {
    return {
        search,
        transportation,
        start,
        end
    };
}

// 최근 검색 리스트에 사용자가 검색한 내용을 추가하는 함수이다.  최근 검색 표시 개수는 최대 10개로 제한해 놓았다.(네이버 길찾기를 참고함.)
function addRecentSearch(type) {
    let recentSearch;
    if (type === SEARCH) recentSearch = makeRecentSearch($("#searchRequestForm").val(), null, null, null);
    else if (type === FIND_PATH) recentSearch = makeRecentSearch(null, $("#transportation").val(), $("#startPoint").val(), $("#endPoint").val());
    //console.log(recentSearch);
    let search = [];
    let previousSearch = JSON.parse(localStorage.getItem("recentSearch"));
    //console.log(JSON.parse(localStorage.getItem("recentSearch")));
    if (previousSearch != null) {
        for (let i = previousSearch.length === 10 ? 1 : 0; i < previousSearch.length; i++) {
            search.push(previousSearch[i]);
        }
        for (let i = 0; i < previousSearch.length; i++) {
            if (JSON.stringify(search[i]) === JSON.stringify(recentSearch)) {
                search.splice(i, 1);
            }
        }
    }
    //console.log(search);
    //console.log(recentSearch);
    search.push(recentSearch);
    //console.log(search);
    localStorage.setItem("recentSearch", JSON.stringify(search));

    showRecentSearchList();
}

// 최근 검색 리스트를 사용자에게 보여주는 함수이다.
function showRecentSearchList() {
    let searchList = JSON.parse(localStorage.getItem("recentSearch"));
    //console.log(JSON.parse(localStorage.getItem("recentSearch")));
    //console.log(searchList.length);
    $("#recentSearch").empty();
    if (searchList == null || searchList.length === 0) {
        $("#recentSearch").hide();
    } else {
        $("#recentSearch").show();
        for (let i = searchList.length - 1; i >= 0; i--) {
            if (searchList[i].search !== null) {
                let text = searchList[i].search.toString();
                $("#recentSearch").append(
                    "<li onselectstart='return false' class='alert alert-dark alert-dismissible' style='list-style: none; padding-bottom: 0; padding-top: 0; margin-bottom: 0.25rem' id='" + (i + "thSearch").toString() + "'>" +
                    "   <div role = 'button' onclick='deleteRecentSearch(" + i + "); searchAgain(\"" + searchList[i].search + "\");'>"
                    + text +
                    "   </div>" +
                    "   <button style='padding: 0.25rem;' type='button' class='btn-close' data-bs-dismiss='alert' aria-label='Close' onclick='deleteRecentSearch(" + i + ")'></button>" +
                    "</li>");
            } else {
                let text = (searchList[i].transportation + (searchList[i].transportation === "자동차" ? "" : "\u00a0\u00a0\u00a0") + " | " + searchList[i].start + " → " + searchList[i].end).toString();
                //console.log(searchList[i]);
                $("#recentSearch").append(
                    "<li onselectstart='return false' class='alert alert-dark alert-dismissible' style='list-style: none; padding-bottom: 0; padding-top: 0; margin-bottom: 0.25rem' id='" + (i + "thSearch").toString() + "'>" +
                    "   <div role = 'button' onclick='deleteRecentSearch(" + i + "); searchAgain(" + null + ", \"" + searchList[i].transportation + "\", \"" + searchList[i].start + "\", \"" + searchList[i].end + "\");'>"
                    + text +
                    "   </div>" +
                    "   <button style='padding: 0.25rem;' type='button' class='btn-close' data-bs-dismiss='alert' aria-label='Close' onclick='deleteRecentSearch(" + i + ")'></button>" +
                    "</li>");
            }
        }
    }
}

// 최근 검색 버튼을 누를 시 다시 해당 검색 결과를 보여주는 함수이다.
function searchAgain(search, transportation, start, end) {
    if (search !== null) {
        $("#searchRequestForm").val(search);
        //findPlace();
        loadPage(0);
    } else {
        selectTransportation(transportation);
        $("#transportation").val(transportation);
        $("#startPoint").val(start);
        $("#endPoint").val(end);
        findPath();
    }
}

// idx번째 최근 검색을 삭제하는 함수이다.
function deleteRecentSearch(idx) {
    let search = [];
    let previousSearch = JSON.parse(localStorage.getItem("recentSearch"));
    //console.log(JSON.parse(localStorage.getItem("recentSearch")));
    for (let i = 0; i < previousSearch.length; i++) search.push(previousSearch[i]);
    search.splice(idx, 1);
    if (!search.length) {
        $("#recentSearch").hide();
        localStorage.removeItem("recentSearch");
    } else localStorage.setItem("recentSearch", JSON.stringify(search));
    showRecentSearchList();
}

// 지도에 두 지점 간의 경로를 그리는 함수이다.
function setMapRoute(serviceType, route, startObjectType = DEFAULT_OBJ_TYPE, endObjectType = DEFAULT_OBJ_TYPE, latitude = DEFAULT_LATITUDE, longitude = DEFAULT_LONGITUDE) {
    removeAllPolyline();
    removeAllMarker();
    removeAllCustomOverlay();
    //if (route === undefined) return;
    // console.log(route);
    for (let i = 0; i < route.length; i++) {
        for (let j = 0; j < route[i].length; j++) {
            if (latitude === route[i][j].latitude && longitude === route[i][j].longitude) setBoundsByRoute(route, i);
            if (!j) continue;
            let linePath = [
                new kakao.maps.LatLng(route[i][j - 1].latitude, route[i][j - 1].longitude),
                new kakao.maps.LatLng(route[i][j].latitude, route[i][j].longitude)
            ]
            let lineColor = '#db4040', lineType = 'solid';
            if ((j === 1 && startObjectType === BUILDING) || (j === route[i].length - 1 && endObjectType === BUILDING)) {
                lineColor = '#808080';
                lineType = 'dashed';
            }
            let polyline = new kakao.maps.Polyline({
                path: linePath, // 선을 구성하는 좌표배열 입니다
                strokeWeight: 5, // 선의 두께 입니다
                strokeColor: lineColor, // 선의 색깔입니다
                strokeOpacity: 0.7, // 선의 불투명도 입니다 1에서 0 사이의 값이며 0에 가까울수록 투명합니다
                strokeStyle: lineType, // 선의 스타일입니다
                clickable: false
            });
            polyline.setMap(map);
            drawRoute.push(polyline);
        }
        if (serviceType === SERVICE1) {
            addMarker(route[i][0].latitude, route[i][0].longitude);
            addMarker(route[i][route[i].length - 1].latitude, route[i][route[i].length - 1].longitude);
        } else if (serviceType === SERVICE2) {
            console.log(userList);
            addCustomOverlay(route[i][0].latitude, route[i][0].longitude, makeCustomOverlayContent(userList[0]));
            addCustomOverlay(route[i][route[i].length - 1].latitude, route[i][route[i].length - 1].longitude, makeCustomOverlayContent(userList[i + 1]));
        }
    }
}

function setBoundsByRoute(route, routeIdx = ROUTE_IDX) {
    if (mapCenterChanged === true) return;
    BoundStatus = BOUND_CHANGED;
    // 지도 범위 재설정에 사용되는 변수들이다.
    let minLat = {latitude: 90, longitude: 0};
    let maxLat = {latitude: -90, longitude: 0};
    let minLng = {latitude: 0, longitude: 180};
    let maxLng = {latitude: 0, longitude: -180};

    for (let i = 0; i < route.length; i++) {
        if (routeIdx !== ROUTE_IDX && routeIdx !== i) continue;
        for (let j = 0; j < route[i].length; j++) {
            if (minLat.latitude > route[i][j].latitude) minLat = route[i][j];
            if (maxLat.latitude < route[i][j].latitude) maxLat = route[i][j];
            if (minLng.longitude > route[i][j].longitude) minLng = route[i][j];
            if (maxLng.longitude < route[i][j].longitude) maxLng = route[i][j];
        }
    }
    let routeBounds = new kakao.maps.LatLngBounds();
    routeBounds.extend(new kakao.maps.LatLng(minLat.latitude, minLat.longitude));
    routeBounds.extend(new kakao.maps.LatLng(maxLat.latitude, maxLat.longitude));
    routeBounds.extend(new kakao.maps.LatLng(minLng.latitude, minLng.longitude));
    routeBounds.extend(new kakao.maps.LatLng(maxLng.latitude, maxLng.longitude));
    map.setBounds(routeBounds);
}

// 서버에게 길찾기 수행을 요청하고 길찾기 결과를 반환받아 길찾기 결과 정보를 사용자에게 제공하는 함수이다.
function findPath() {
    const begin = new Date();
    console.log("findPath() 호출됨")
    $("#findPathSection").attr('class', 'mb-5');
    resetPathError();
    $("#searchPlaceSection").attr('class', 'mt-3 mb-5');
    resetPlaceError();
    if (!isTransportationsEmpty() || !isStartEmpty() || !isEndEmpty()) return;

    /*====================================================================================================*/
    /*출발지, 도착지 정점 아이디 찾기*/
    let searchStartContent = $("#startPoint").val();
    let searchEndContent = $("#endPoint").val();
    let roadVertexStartId, roadVertexEndId, sidewalkVertexStartId, sidewalkVertexEndId;
    let startObjectType, endObjectType;
    let isReturn = false;
    $.ajax({
        type: "GET",
        url: "/searchPlace",
        async: false,
        data: {
            searchContent: searchStartContent
        },
        success: function (response) {
            console.log(response);
            if (!response.name) {
                $("#findPathError").text("올바른 출발지를 입력해 주세요.").show();
                $("#startPoint").attr('class', "form-control fieldError").focus();
                isReturn = true;
                return;
            }
            roadVertexStartId = response.roadVertexId;
            sidewalkVertexStartId = response.sidewalkVertexId;
            startObjectType = response.objectType;
        },
        error: function (error) {
            $("#findPathError").text("올바른 출발지를 입력해 주세요.").show();
            $("#startPoint").attr('class', "form-control fieldError").focus();
        }
    });
    if (isReturn) return;
    $.ajax({
        type: "GET",
        url: "/searchPlace",
        async: false,
        data: {
            searchContent: searchEndContent
        },
        success: function (response) {
            console.log(response);
            if (!response.name) {
                $("#findPathError").text("올바른 도착지를 입력해 주세요.").show();
                $("#endPoint").attr('class', "form-control fieldError").focus();
                isReturn = true;
                return;
            }
            roadVertexEndId = response.roadVertexId;
            sidewalkVertexEndId = response.sidewalkVertexId;
            endObjectType = response.objectType;
        },
        error: function (error) {
            $("#findPathError").text("올바른 도착지를 입력해 주세요.").show();
            $("#endPoint").attr('class', "form-control fieldError").focus();
        }
    });
    if (isReturn) return;
    if ($("#transportation").val() === "자동차") {
        $("#start").val(roadVertexStartId);
        $("#end").val(roadVertexEndId);
    } else {
        $("#start").val(sidewalkVertexStartId);
        $("#end").val(sidewalkVertexEndId);
    }
    /**
     * 길찾기 사이트에서 출발지와 도착지를 정점 아이디로 검색하고 싶다면
     * 윗 부분을 주석 처리하고 아랫부분의 주석을 해제하면 됨.
     */
    /*$("#start").val($("#startPoint").val());
    $("#end").val($("#endPoint").val());*/
    /*====================================================================================================*/

    let graphRequestForm = $("#graphRequestForm").serialize();
    //console.log(graphRequestForm);
    $.ajax({
        type: "get",
        url: "/path?" + graphRequestForm,
        success: function (response) {
            $(".offcanvas").offcanvas('hide');
            console.log(response);
            let route = [];
            route.push(response.path);
            /*====================================================================================================*/
            /*길찾기 경로 지도에 표시*/
            //console.log('distance: ' + response.distance);
            resetSearchForm();

            setMapRoute(SERVICE1, route, startObjectType, endObjectType);
            /*====================================================================================================*/


            /*====================================================================================================*/
            /*시간 계산*/
            let timeText = "";
            let speed = response.speed * 1000 / 60;
            let minutes = Math.round(response.distance / speed);
            let hours = Math.floor(minutes / 60);
            minutes %= 60;
            if (hours > 0) timeText += hours.toString() + "시간 ";
            timeText += minutes.toString() + "분";
            //console.log(speed);
            $("#time").text(timeText);
            /*====================================================================================================*/


            /*====================================================================================================*/
            /*거리 계산*/
            let distanceText = "\u00a0";
            let distance = response.distance / 1000;
            //console.log(distance);
            if (distance >= 1) distanceText += (Math.round(distance * 10) / 10).toString() + "km";
            else distanceText += Math.round(distance * 1000).toString() + "m";
            $("#distance").text(distanceText);
            /*====================================================================================================*/


            /*====================================================================================================*/
            /*길찾기 결과의 거리, 시간 출력*/
            $("#findPathSection").attr('class', 'mb-3');
            $("#pathInfoSection").show();
            /*====================================================================================================*/


            /*====================================================================================================*/
            /*최근 검색 추가.*/
            addRecentSearch(FIND_PATH);
            /*====================================================================================================*/


            /*====================================================================================================*/
            /*지도 범위 재설정*/
            setBoundsByRoute(route);
            /*====================================================================================================*/
        },
        error: function (error) {
            //alert("에러 발생!");
            //console.log(error);
            //console.log(error.responseJSON);

            let isEnd = false;
            error.responseJSON.find(function (err) {
                if (err.field !== "transportation") return;
                isEnd = true;
                $("#findPathError").text(err.message).show();
                $("#transportation").attr('class', "form-control fieldError").focus();
            });
            if (isEnd) return;
            error.responseJSON.find(function (err) {
                if (err.field !== "start") return;
                isEnd = true;
                $("#findPathError").text(err.message).show();
                $("#startPoint").attr('class', "form-control fieldError").focus();
            });
            if (isEnd) return;
            error.responseJSON.find(function (err) {
                if (err.field !== "end") return;
                isEnd = true;
                $("#findPathError").text(err.message).show();
                $("#endPoint").attr('class', "form-control fieldError").focus();
            });
        }
    }).then(() => {
        const end = new Date();
        const milliTime = end - begin;
        let txt = "길 찾기에 소요된 시간: " + milliTime + "ms";
        $("#responseTime").text(txt);
        //console.log("길 찾기 종료. 소요된 시간: " + milliTime + "ms");
    });
}

function setBounds(response) {
    // LatLngBounds 객체에 추가된 좌표들을 기준으로 지도의 범위를 재설정합니다
    // 이때 지도의 중심좌표와 레벨이 변경될 수 있습니다
    console.log("지도 범위 재설정 하기");
    // 버튼을 클릭하면 아래 배열의 좌표들이 모두 보이게 지도 범위를 재설정합니다
    var points = [
        new kakao.maps.LatLng(response.latitude, response.longitude)
    ];

    // 지도를 재설정할 범위정보를 가지고 있을 LatLngBounds 객체를 생성합니다
    var bounds = new kakao.maps.LatLngBounds();

    // LatLngBounds 객체에 좌표를 추가합니다
    bounds.extend(points[0]);
    map.setBounds(bounds);
}

function resetPathError() {
    $("#startPoint").attr('class', "form-control");
    $("#endPoint").attr('class', "form-control");
    $("#transportation").attr('class', "form-control");
    $("#findPathError").hide();
}

function isStartEmpty() {
    if ($("#startPoint").val() === "") {
        resetPathError();
        $("#startPoint").attr('class', "form-control fieldError").focus();
        $("#findPathError").text('출발지를 입력해 주세요.').show();
        return false;
    }
    return true;
}

function isEndEmpty() {
    if ($("#endPoint").val() === "") {
        resetPathError();
        $("#endPoint").attr('class', "form-control fieldError").focus();
        $("#findPathError").text('도착지를 입력해 주세요.').show();
        return false;
    }
    return true;
}

function isTransportationsEmpty() {
    if ($("#transportation").val() === "") {
        resetPathError();
        $("#transportation").attr('class', "form-control fieldError").focus();
        $("#findPathError").text('이동 수단을 선택해 주세요.').show();
        return false;
    }
    return true;
}

function resetPlaceError() {
    $("#searchRequestForm").attr('class', "form-control");
    $("#searchPlaceError").hide();
}

function isPlaceEmpty() {
    if ($("#searchRequestForm").val() === "") {
        resetPlaceError();
        $("#searchRequestForm").attr('class', "form-control fieldError").focus();
        $("#searchPlaceError").text('검색 내용을 입력해주세요').show();
        return false;
    }
    return true;
}

// 길찾기에서 출발지와 도착지를 바꾸는 함수이다.
function changeStartEnd() {
    let startPoint = $("#startPoint").val();
    $("#startPoint").val($("#endPoint").val());
    $("#endPoint").val(startPoint);
}

// 검색 결과에서 출발 버튼을 누르면 해당 검색 결과가 출발지로 설정되는 함수이다.
function setSearchStartPoint(value) {
    $("#startPoint").val(value);
    goToHome();
}

// 검색 결과에서 도착 버튼을 누르면 해당 검색 결과가 도착지로 설정되는 함수이다.
function setSearchEndPoint(value) {
    $("#endPoint").val(value);
    goToHome();
}

// 길찾기, 최근 검색을 사용자에게 보여주는 함수이다.
function goToHome() {
    $("#searchRequestForm").val("");
    $("#searchInfoSection").hide();
    $("#pageInfoSection").hide();
    $("#findPathSection").show();
    $("#recentSearchSection").show();
    $("#homeButton").hide();
    removeAllMarker();
}

/**
 * 웹 페이지의 클릭 위치에 따라 $inputForm 입력 창 밑의 $searchList의 표시 여부를 변경하는 함수이다.
 */
function changeAutoCompleteListDisplayType($inputForm, $searchList) {
    // searchPlaceSection이 아닌 다른 곳을 클릭하면 objects 자동 완성을 숨기는 기능을 한다.
    $(document).click(function () {
        let objectsName = $($inputForm);
        if (!objectsName.is(event.target) && !objectsName.has(event.target).length && !objectsName.is(":focus")) {
            //console.log("click: " + $inputForm);
            $($searchList).hide();
        }
    });

    $(document).focusin(function () {
        let objectsName = $($inputForm);
        if (!objectsName.is(event.target) && !objectsName.has(event.target).length && !objectsName.is(":focus") && !$($searchList).children().is(":focus")) {
            //console.log("focus: " + $inputForm);
            $($searchList).hide();
        }
    });

    // objects name에 해당하는 인풋 태그가 포커스되면 닉네임 자동 완성을 표시하는 기능을 한다.
    $($inputForm).on("focus", function () {
        $($searchList).show();
    })
}

/**
 * $inputForm에 해당하는 인풋 태그의 value가 달라지면 서버로부터 objects 자동 완성 리스트를 요청하고 objects 자동 완성 목록을 생성하는 함수이다.
 */
function changeAutoCompleteList($inputForm, $searchList, $error) {
    let previousObjectsNameInput = "";

    $($inputForm).on("input", function (e) {
        if (previousObjectsNameInput === $($inputForm).val()) return;
        previousObjectsNameInput = $($inputForm).val();

        if ($($inputForm).val() === "") {
            $($searchList).children().remove();
            return;
        }
        $($error).hide();
        $($inputForm).attr('class', "form-control");
        $.ajax({
            type: "GET",
            url: "/searchObjectsName",
            data: {
                searchWord: $($inputForm).val()
            },
            success: function (response) {
                let objectsNameList = response.objectsNameList;
                $($searchList).children().remove();
                objectsNameList.forEach(objectsName => {
                    if (objectsNameList.length !== 1 || objectsName !== $($inputForm).val()) {
                        $($searchList).append(
                            "<button type='button' class='list-group-item list-group-item-action' onclick='$(\"" + $inputForm + "\").val(\"" + objectsName + "\"); $(\"" + $searchList + "\").children().remove();' tabindex='0'>" +
                            objectsName +
                            "</button>"
                        );
                    }
                });
            },
            error: function (error) {
                console.log(error);
            }
        });
    });
}

$("#findPathSection").show();
$("#recentSearchSection").show();
showRecentSearchList();
changeAutoCompleteListDisplayType("#searchRequestForm", "#objectsNameSearchList");
changeAutoCompleteList("#searchRequestForm", "#objectsNameSearchList", "#searchPlaceError");
changeAutoCompleteListDisplayType("#startPoint", "#startPointAutoCompleteList");
changeAutoCompleteList("#startPoint", "#startPointAutoCompleteList", "#findPathError");
changeAutoCompleteListDisplayType("#endPoint", "#endPointAutoCompleteList");
changeAutoCompleteList("#endPoint", "#endPointAutoCompleteList", "#findPathError");