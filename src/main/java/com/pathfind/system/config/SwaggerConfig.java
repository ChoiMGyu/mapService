/*
 * 클래스 기능 : swagger config 클래스이다.
 * 최근 수정 일자 : 2024.07.20(토)
 */
package com.pathfind.system.config;

import com.pathfind.system.customAnnotation.ApiErrorCode;
import com.pathfind.system.exception.BasicErrorCode;
import com.pathfind.system.exception.ErrorReason;
import com.pathfind.system.exception.ErrorVCResponse;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.examples.Example;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import lombok.*;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.HandlerMethod;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static java.util.stream.Collectors.groupingBy;

@Configuration
public class SwaggerConfig {
    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI().components(new Components()).info(apiInfo());
    }

    private Info apiInfo() {
        return new Info()
                .title("영남대 길 찾기 서비스")
                .description("<영남대 길 찾기 서비스> api 문서")
                .version("0.0.1-SNAPSHOT");
    }

    @Bean
    public OperationCustomizer customize() {
        return (Operation operation, HandlerMethod handlerMethod) -> {
            ApiErrorCode apiErrorCodeExample = handlerMethod.getMethodAnnotation(ApiErrorCode.class);
            // ApiErrorCodeExample 어노테이션 단 메소드 적용
            if (apiErrorCodeExample != null) {
                generateErrorCodeResponse(operation, handlerMethod.getMethodAnnotation(ApiErrorCode.class).value());
            }
            return operation;
        };
    }

    private void generateErrorCodeResponse(Operation operation, Class<? extends BasicErrorCode> type) {
        ApiResponses responses = operation.getResponses();
        // 해당 이넘에 선언된 에러코드들의 목록을 가져옵니다.
        BasicErrorCode[] errorCodes = type.getEnumConstants();
        // 400, 401, 404 등 에러코드의 상태코드들로 리스트로 모읍니다.
        // 400 같은 상태코드에 여러 에러코드들이 있을 수 있습니다.
        Map<Integer, List<ExampleHolder>> statusWithExampleHolders = Arrays.stream(errorCodes)
                .map(
                        basicErrorCode -> {
                            try {
                                ErrorReason errorReason = basicErrorCode.getErrorReason();
                                ErrorVCResponse errorVCResponse = basicErrorCode.getErrorVCResponse();
                                return ExampleHolder.builder()
                                        .holder(getSwaggerExample(errorVCResponse))
                                        .code(errorReason.getStatus())
                                        .name(errorReason.getCode())
                                        .build();
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                )
                .collect(groupingBy(ExampleHolder::getCode));
        // response 객체들을 responses 에 넣습니다.
        addExamplesToResponses(responses, statusWithExampleHolders);
    }

    //ExampleHolder
    @Getter
    @Builder(builderMethodName = "innerBuilder")
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    @AllArgsConstructor(access = AccessLevel.PROTECTED)
    public static class ExampleHolder {
        // 스웨거의 Example 객체입니다. 위 스웨거 분석의 Example Object 참고.
        private Example holder;
        private String name;
        private int code;

        public static ExampleHolderBuilder builder() {
            return innerBuilder();
        }
    }

    private Example getSwaggerExample(ErrorVCResponse errorVCResponse) {
        //ErrorResponse 는 클라이언트한 실제 응답하는 공통 에러 응답 객체입니다.
        Example example = new Example();
        example.setValue(errorVCResponse);
        return example;
    }

    private void addExamplesToResponses(ApiResponses responses, Map<Integer, List<ExampleHolder>> statusWithExampleHolders) {
        statusWithExampleHolders.forEach(
                (status, v) -> {
                    Content content = new Content();
                    MediaType mediaType = new MediaType();
                    // 상태 코드마다 ApiResponse을 생성합니다.
                    ApiResponse apiResponse = new ApiResponse();
                    //  List<ExampleHolder> 를 순회하며, mediaType 객체에 예시값을 추가합니다.
                    v.forEach(
                            exampleHolder -> mediaType.addExamples(
                                    exampleHolder.getName(), exampleHolder.getHolder()));
                    // ApiResponse 의 content 에 mediaType을 추가합니다.
                    content.addMediaType("application/json", mediaType);
                    apiResponse.setContent(content);
                    // 상태코드를 key 값으로 responses 에 추가합니다.
                    responses.addApiResponse(status.toString(), apiResponse);
                }
        );
    }
}
