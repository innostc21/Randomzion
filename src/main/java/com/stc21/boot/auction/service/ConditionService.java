package com.stc21.boot.auction.service;

import com.stc21.boot.auction.dto.ConditionDto;
import com.stc21.boot.auction.entity.Condition;
import org.springframework.data.domain.Sort;

import java.util.List;
import java.util.Optional;

public interface ConditionService {
    List<ConditionDto> getAllConditions();
    List<ConditionDto> getAllSorted(Sort sort);
    List<ConditionDto> getAllSortedEvenDeleted(Sort sort);
    ConditionDto convertToDto(Condition condition);
    List<Condition> findAll();
    Optional<Condition> getById(long id);

    void setDeletedTo(long id, boolean newValue);
    Condition save(ConditionDto conditionDto);
}
