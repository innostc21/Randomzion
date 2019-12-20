package com.stc21.boot.auction.advice;

import com.stc21.boot.auction.exception.ConcurrentBuyException;
import com.stc21.boot.auction.exception.NotEnoughMoneyException;
import com.stc21.boot.auction.exception.PageNotFoundException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class AppWideExceptionHandler {

    @ExceptionHandler(PageNotFoundException.class)
    public String pageNotFound() {
        return "errors/pageNotFound";
    }

    @ExceptionHandler(NotEnoughMoneyException.class)
    public String notEnoughMoney() {
        return "errors/notEnoughMoney";
    }

    @ExceptionHandler(ConcurrentBuyException.class)
    public String concurrentBuy() {
        return "errors/tooSlowPage";
    }

}
