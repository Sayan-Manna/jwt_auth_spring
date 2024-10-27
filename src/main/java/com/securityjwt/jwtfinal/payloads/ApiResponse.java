package com.securityjwt.jwtfinal.payloads;



public class ApiResponse {
    private String message;
    private Integer status;
    public ApiResponse(Integer status, String message) {
        this.status = status;
        this.message = message;
    }
    public ApiResponse() {
    }
    public String getMessage() {
        return message;
    }
    public void setMessage(String message) {
        this.message = message;
    }
    public Integer getStatus() {
        return status;
    }

    public void setStatus(Integer status) {
        this.status = status;
    }

}


