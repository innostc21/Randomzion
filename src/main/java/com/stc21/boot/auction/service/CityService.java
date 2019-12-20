package com.stc21.boot.auction.service;

import com.stc21.boot.auction.dto.CityDto;
import com.stc21.boot.auction.entity.City;
import org.springframework.data.domain.Sort;

import java.util.List;
import java.util.Optional;

public interface CityService {
    List<City> findAll();
    List<CityDto> getAllSorted(Sort sort);
    List<CityDto> getAllSortedEvenDeleted(Sort sort);
    CityDto convertToDto(City city);
    List<CityDto> getAllCities();
    Optional<City> getById(long id);

    void setDeletedTo(long id, boolean newValue);
    City save(CityDto cityDto);
}
