package com.stc21.boot.auction.scheduler;

import com.stc21.boot.auction.dto.LotDto;
import com.stc21.boot.auction.entity.Lot;
import com.stc21.boot.auction.service.LotService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.persistence.Access;
import java.util.List;

@Component
@Slf4j
public class LotPriceScheduler {

    private final LotService lotService;

    @Autowired
    public LotPriceScheduler(@Qualifier(value = "lotServiceImpl") LotService lotService) {
        this.lotService = lotService;
    }

    @Scheduled(cron = "0,30 * * * * *")
    public void updateLots() {
        log.info("< update Lots");
        List<Lot> lots = lotService.getUnboughtLots();
        lotService.updateAllLots(lots);
        log.info("> update Lots");
    }
}
