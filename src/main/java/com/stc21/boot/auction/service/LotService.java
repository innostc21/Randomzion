package com.stc21.boot.auction.service;

import com.stc21.boot.auction.dto.LotDto;
import com.stc21.boot.auction.entity.Lot;
import org.springframework.data.domain.Example;
import com.stc21.boot.auction.exception.NotEnoughMoneyException;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.data.domain.Page;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface LotService {
    LotDto findById(long id);
    Page<LotDto> getPaginated(Pageable pageable);
    Page<LotDto> getPaginated(Lot exampleLot, Pageable pageable);

    Lot saveNewLot(LotDto lotDto, Authentication token, MultipartFile[] images);
    void sale(String username, LotDto lotDto) throws NotEnoughMoneyException;
    void updateAllLots(List<Lot> lots);

    void setDeletedTo(long id, boolean newValue);
    LotDto convertToDto(Lot lot);

    List<Lot> getUnboughtLots();
    Page<LotDto> getUnboughtLots(Lot exampleLot, Pageable pageable);
    Page<LotDto> getBoughtLotsOf(String username, Pageable pageable);
    Page<LotDto> getUnboughtLotsOf(String username, Pageable pageable);
    Page<LotDto> getBoughtLotsBy(String username, Pageable pageable);
}
