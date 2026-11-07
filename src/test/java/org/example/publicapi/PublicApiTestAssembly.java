package org.example.publicapi;

import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * 公网 API 测试装配器：<b>一份</b>共享 {@link PublicApiSupport} + 五个按域 controller。
 *
 * <p>历史上测试直接 {@code new PublicApiController()} 并把 {@code PublicApiSupport} 的字段用
 * {@code ReflectionTestUtils.setField} 注到门面上；门面删除后，测试改为由本类组装真实的生产 bean
 * 拓扑，再对五个域 controller 建 {@code standaloneSetup} —— 请求路径、参数与断言都不变，
 * 变的只是"被测对象是真实的域 controller"，而不是转发壳。
 *
 * <p><b>依赖顺序有讲究</b>：{@link PublicHomeController} 的构造依赖 Alert 与 Geo
 * （{@code /home} 是三块快照的组合），所以必须 alert → geo → home → kb → misc。
 *
 * <p>注意：{@code standaloneSetup} 只注册传入实例自己声明的 {@code @RequestMapping}，
 * 因此五个域 controller 必须<b>同时</b>传入，缺一个就会得到 404 而不是"另一个 controller 接手"。
 */
final class PublicApiTestAssembly {

    /** 共享状态：缓存 Snapshot、限流桶、上游服务等全部在这里，测试的 setField 目标是它的字段。 */
    final PublicApiSupport support;

    final PublicAlertController alertController;
    final PublicGeoController geoController;
    final PublicHomeController homeController;
    final PublicKbController kbController;
    final PublicMiscController miscController;

    /** 与生产同构的定时预热组件（测试只按需调用，不会被调度器触发）。 */
    final PublicSnapshotWarmer snapshotWarmer;

    PublicApiTestAssembly() {
        this.support = new PublicApiSupport();
        this.alertController = new PublicAlertController(support);
        this.geoController = new PublicGeoController(support);
        this.homeController = new PublicHomeController(support, alertController, geoController);
        this.kbController = new PublicKbController(support);
        this.miscController = new PublicMiscController(support);
        this.snapshotWarmer = new PublicSnapshotWarmer(
                support, alertController, homeController, geoController, miscController);
    }

    /** 五个域 controller 的 {@code standaloneSetup}；顺序与构造顺序一致，便于对照。 */
    MockMvc mvc() {
        return builder().build();
    }

    /** 需要追加拦截器/过滤器的测试用这个（例如 CORS 别名测试）。 */
    org.springframework.test.web.servlet.setup.StandaloneMockMvcBuilder builder() {
        return MockMvcBuilders.standaloneSetup(
                alertController, homeController, kbController, geoController, miscController);
    }
}
