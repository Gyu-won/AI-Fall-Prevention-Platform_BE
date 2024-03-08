package happyaging.server.exception.errorcode;

import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;

@AllArgsConstructor
public enum AppErrorCode implements ErrorCode {
    INVALID_USER(HttpStatus.UNAUTHORIZED, "존재하지 않는 회원입니다."),
    INVALID_SENIOR(HttpStatus.NOT_FOUND, "존재하지 않는 시니어입니다."),
    INVALID_QUESTION(HttpStatus.NOT_FOUND, "존재하지 않는 질문입니다."),
    INVALID_OPTION(HttpStatus.NOT_FOUND, "존재하지 않는 선택지입니다."),
    INVALID_RESULT(HttpStatus.NOT_FOUND, "존재하지 않는 결과입니다."),
    INVALID_FILE(HttpStatus.NOT_FOUND, "존재하지 않는 보고서입니다."),
    INVALID_BIRTH(HttpStatus.NOT_FOUND, "올바르지 않은 출생년도입니다."),
    DISCONNECT_AI_SERVER(HttpStatus.INTERNAL_SERVER_ERROR, "AI 서버 에러입니다."),
    INVALID_PRODUCT(HttpStatus.NOT_FOUND, "존재하지않는 물품입니다."),
    CANNOT_SAVE_IMAGES(HttpStatus.INTERNAL_SERVER_ERROR, "이미지를 저장할 수 없습니다."),
    INVALID_LOCATION(HttpStatus.NOT_FOUND, "올바르지 않은 위치입니다."),
    INVALID_SURVEY(HttpStatus.NOT_FOUND, "존재하지 않는 설문조사입니다."),
    INVALID_INSTALL_IMAGE(HttpStatus.NOT_FOUND, "존재하지 않는 설치사진입니다."),
    INVALID_QUESTION_NUMBER(HttpStatus.BAD_REQUEST, "유효하지 않은 번호입니다."),
    INVALID_ACCOUNT(HttpStatus.BAD_REQUEST, "일치하는 계정을 찾을 수 없습니다."),
    INVALID_ADMIN(HttpStatus.UNAUTHORIZED, "관리자로 등록되지 않은 계정입니다."),
    DISABLE_TO_CONVERT_EXCEL(HttpStatus.INTERNAL_SERVER_ERROR, "엑셀 파일로 변환에 실패하였습니다."),
    INVALID_JOIN(HttpStatus.BAD_REQUEST, "올바르지 않은 회원가입 요청입니다.");

    private final HttpStatus httpStatus;
    private final String message;

    @Override
    public String getMessage() {
        return message;
    }

    @Override
    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
