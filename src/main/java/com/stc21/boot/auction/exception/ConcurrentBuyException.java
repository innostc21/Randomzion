package com.stc21.boot.auction.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value= HttpStatus.PAYLOAD_TOO_LARGE, reason="IT'S TOO LARGE")
public class ConcurrentBuyException extends RuntimeException{
    public ConcurrentBuyException(String message) {
        super(message);
    }
}
