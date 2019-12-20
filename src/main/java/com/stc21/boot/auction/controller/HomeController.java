package com.stc21.boot.auction.controller;

import com.stc21.boot.auction.dto.LotDto;
import com.stc21.boot.auction.entity.Lot;
import com.stc21.boot.auction.service.*;
import org.springframework.data.domain.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;


@Controller
@RequestMapping(path = "/")
@SessionAttributes("queryParams")
public class HomeController {

    private final UserService userService;
    private final LotService lotService;
    private final CategoryService categoryService;
    private final CityService cityService;
    private final ConditionService conditionService;
    private final Map<String, String> defaultParams = new HashMap<String, String>(){{
        put("page", "1");
        put("sortBy", "creationTime");
        put("sortDir", "desc");
        put("categoryFilter", "-1");
        put("cityFilter", "-1");
        put("conditionFilter", "-1");
        put("searchText", "");
        put("selectOption", "name");
    }};

    public HomeController(UserService userService, LotService lotService, CategoryService categoryService, CityService cityService, ConditionService conditionService) {
        this.userService = userService;
        this.lotService = lotService;
        this.categoryService = categoryService;
        this.cityService = cityService;
        this.conditionService = conditionService;
    }

    @ModelAttribute("queryParams")
    Map<String, String> queryParams() {
        return new HashMap<String, String>() {{
            putAll(defaultParams);
        }};
    }

    // возвращает результат постранично
    @GetMapping(path = "/")
    public String showHomePage(
            Model model,
            @ModelAttribute("queryParams") Map<String, String> queryParams,
            @RequestParam Map<String, String> requestParams) {

        if (requestParams.size() == 0)
            queryParams.putAll(defaultParams);
        else
            queryParams.putAll(requestParams);

        if (!requestParams.containsKey("page"))
            queryParams.put("page", defaultParams.get("page"));

        /* ----- */

        Lot exampleLot = new Lot();
        String selectOption = queryParams.get("selectOption").trim();
        String searchText = queryParams.get("searchText").trim();
        if (!selectOption.equals("")) {
            switch (selectOption) {
                default: /* name */ exampleLot.setName(searchText); break;
                case "description": exampleLot.setDescription(searchText); break;
            }
        }
        exampleLot .setCategory( categoryService.getById(Integer.parseInt(queryParams.get( "categoryFilter"))).orElse(null));
        exampleLot     .setCity(     cityService.getById(Integer.parseInt(queryParams.get(     "cityFilter"))).orElse(null));
        exampleLot.setCondition(conditionService.getById(Integer.parseInt(queryParams.get("conditionFilter"))).orElse(null));

        Sort sort = Sort.by(queryParams.get("sortDir").equals("asc") ? Sort.Direction.ASC : Sort.Direction.DESC, queryParams.get("sortBy"));
        PageRequest pageRequest = PageRequest.of(Integer.parseInt(queryParams.get("page")) - 1, 5, sort);

        /* ----- */

        Page<LotDto> pagedHomePageLots = lotService.getUnboughtLots(exampleLot, pageRequest);
        model.addAttribute("lots", pagedHomePageLots);

        model.addAttribute("categories",  categoryService.findAll());
        model.addAttribute(    "cities",      cityService.findAll());
        model.addAttribute("conditions", conditionService.findAll());

        model.addAttribute( "categoryFilter", Integer.parseInt(queryParams.get( "categoryFilter")));
        model.addAttribute(     "cityFilter", Integer.parseInt(queryParams.get(     "cityFilter")));
        model.addAttribute("conditionFilter", Integer.parseInt(queryParams.get("conditionFilter")));
        model.addAttribute(     "searchText",                  queryParams.get(     "searchText"));
        model.addAttribute(   "selectOption",                  queryParams.get(   "selectOption"));

        return "home";
    }

}
