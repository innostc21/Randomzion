package com.stc21.boot.auction.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value= HttpStatus.I_AM_A_TEAPOT, reason="I_AM_A_TEAPOT")
public class NotEnoughMoneyException extends RuntimeException {

    private static final long serialVersionUID = -3128681006635769411L;

    public NotEnoughMoneyException(String message) {
        super(message);
    }

}